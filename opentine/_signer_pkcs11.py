"""``pkcs11:...``: sign with an Ed25519 key inside an HSM (``opentine[pkcs11]``).

The URI follows RFC 7512: path attributes ``token`` and ``object`` (labels) and
optionally ``id`` (hex), query attributes ``module-path`` and ``pin-value`` or
``pin-source=env:VAR``. Missing parts fall back to ``OPENTINE_PKCS11_MODULE``
and ``OPENTINE_PKCS11_PIN``. The key is ``CKK_EC_EDWARDS`` and signs with
``CKM_EDDSA`` (pure Ed25519), e.g.::

    pkcs11:token=opentine;object=proxy?module-path=/usr/lib/softhsm/libsofthsm2.so
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import unquote

from opentine._signer import BaseSigner
from opentine._signing_keys import SignatureError

MODULE_ENV = "OPENTINE_PKCS11_MODULE"
PIN_ENV = "OPENTINE_PKCS11_PIN"


def parse_uri(uri: str) -> dict[str, str]:
    """RFC 7512 path and query attributes, percent-decoded."""
    if not uri.startswith("pkcs11:"):
        raise SignatureError("a PKCS#11 signer URI starts with pkcs11:")
    path, _, query = uri[len("pkcs11:") :].partition("?")
    found: dict[str, str] = {}
    for part in [*path.split(";"), *query.split("&")]:
        if part:
            name, sep, value = part.partition("=")
            if not sep:
                raise SignatureError(f"pkcs11 URI attribute {name!r} has no value")
            found[name.strip()] = unquote(value)
    return found


def _pin(attrs: dict[str, str]) -> str | None:
    if "pin-value" in attrs:
        return attrs["pin-value"]
    source = attrs.get("pin-source", "")
    if source.startswith("env:"):
        return os.environ.get(source[4:])
    if source:
        raise SignatureError("pkcs11 pin-source must be env:VAR")
    return os.environ.get(PIN_ENV)


def _point(value: bytes) -> bytes:
    """CKA_EC_POINT: a DER OCTET STRING around the 32-byte key, or the bare key."""
    raw = bytes(value)
    if len(raw) == 34 and raw[0] == 0x04 and raw[1] == 32:
        return raw[2:]
    if len(raw) == 32:
        return raw
    raise SignatureError("the PKCS#11 public key is not a 32-byte Ed25519 point")


class Pkcs11Signer(BaseSigner):
    def __init__(self, uri: str, lib: Any = None) -> None:
        try:
            import pkcs11  # optional extra
        except ImportError as exc:
            raise SignatureError("pkcs11 signers need: pip install 'opentine[pkcs11]'") from exc
        self._pkcs11 = pkcs11
        self.attrs = parse_uri(uri)
        path, _, query = uri.partition("?")
        kept = [part for part in query.split("&") if part and not part.startswith("pin-value=")]
        self.uri = path + ("?" + "&".join(kept) if kept else "")  # never echo a pin-value
        module = self.attrs.get("module-path") or os.environ.get(MODULE_ENV)
        if lib is None and not module:
            raise SignatureError(f"pkcs11: name the module (module-path=...) or set {MODULE_ENV}")
        try:
            self._lib = lib if lib is not None else pkcs11.lib(module)
        except (OSError, RuntimeError, pkcs11.PKCS11Error) as exc:
            raise SignatureError(f"pkcs11: cannot load {module}: {exc}") from exc
        self._public = self._with_session(lambda session: _point(self._find(session, False)))

    def _with_session(self, action: Any) -> Any:
        pkcs11 = self._pkcs11
        try:
            token = self._lib.get_token(token_label=self.attrs.get("token"))
            with token.open(user_pin=_pin(self.attrs)) as session:
                return action(session)
        except pkcs11.PKCS11Error as exc:
            raise SignatureError(f"pkcs11: {type(exc).__name__} {exc}") from exc

    def _find(self, session: Any, private: bool) -> Any:
        from pkcs11 import Attribute, KeyType, ObjectClass

        query: dict[str, Any] = {
            "object_class": ObjectClass.PRIVATE_KEY if private else ObjectClass.PUBLIC_KEY,
            "key_type": KeyType.EC_EDWARDS,
        }
        if "object" in self.attrs:
            query["label"] = self.attrs["object"]
        if "id" in self.attrs:
            query["id"] = bytes.fromhex(self.attrs["id"].replace("%", ""))
        key = session.get_key(**query)
        return key if private else key[Attribute.EC_POINT]

    @property
    def public_key(self) -> bytes:
        return self._public

    def sign(self, message: bytes) -> bytes:
        from pkcs11 import Mechanism

        def action(session: Any) -> bytes:
            return bytes(self._find(session, True).sign(message, mechanism=Mechanism.EDDSA))

        return self._with_session(action)


__all__ = ["MODULE_ENV", "PIN_ENV", "Pkcs11Signer", "parse_uri"]
