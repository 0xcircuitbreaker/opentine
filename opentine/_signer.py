"""One ``Signer`` interface for every Ed25519 signature opentine makes (0.41, X24).

A signer is anything with::

    sign(message: bytes) -> bytes   # a 64-byte Ed25519 signature
    public_key: bytes               # the 32-byte raw public key
    algorithm: str                  # "ed25519"
    key_id: str                     # "sha256:<hex>" of the public key

and is named by a URI wherever a signing key path is accepted:

* ``file:PATH`` (or a bare path) -- an encrypted PKCS#8 file (``_key_store``);
* ``ssh-agent:FINGERPRINT`` -- an Ed25519 key held by ``ssh-agent``;
* ``pkcs11:token=...;object=...?module-path=...`` -- an HSM (``opentine[pkcs11]``);
* ``kms:aws:ARN`` / ``kms:gcp:RESOURCE`` -- a cloud KMS key (``opentine[kms-aws]``,
  ``opentine[kms-gcp]``).

Signing paths keep taking what ``ed25519_private_from_file`` returns: a
:class:`SignerKey`, which looks like ``Ed25519PrivateKey`` (``sign`` and
``public_key()``) and checks every signature a backend returns before using it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

SCHEMES = ("file", "ssh-agent", "pkcs11", "kms")


@runtime_checkable
class Signer(Protocol):
    algorithm: str

    @property
    def public_key(self) -> bytes: ...

    @property
    def key_id(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


class BaseSigner:
    """Shared ``algorithm`` / ``key_id`` for the Ed25519 backends."""

    algorithm = "ed25519"
    uri = ""

    @property
    def public_key(self) -> bytes:  # pragma: no cover - every backend overrides
        raise NotImplementedError

    @property
    def key_id(self) -> str:
        from opentine._signing_pins import key_fingerprint

        return key_fingerprint(self.public_key)

    def sign(self, message: bytes) -> bytes:  # pragma: no cover - every backend overrides
        raise NotImplementedError


class LocalSigner(BaseSigner):
    """An in-process ``Ed25519PrivateKey`` (from a file, or freshly generated)."""

    def __init__(self, private: Any, uri: str = "") -> None:
        self._private = private
        self.uri = uri

    @property
    def public_key(self) -> bytes:
        return self._private.public_key().public_bytes_raw()

    def sign(self, message: bytes) -> bytes:
        return self._private.sign(message)


class SignerKey:
    """A :class:`Signer` dressed as an ``Ed25519PrivateKey`` for the signing paths."""

    def __init__(self, signer: Any) -> None:
        if getattr(signer, "algorithm", None) != "ed25519":
            from opentine._signing_keys import SignatureError

            raise SignatureError(f"unsupported signer algorithm {signer.algorithm!r}")
        self.signer = signer
        self._public: Any = None

    def public_key(self) -> Any:
        if self._public is None:
            from opentine._signing_keys import coerce_ed25519_public

            self._public = coerce_ed25519_public(bytes(self.signer.public_key))
        return self._public

    def sign(self, message: bytes) -> bytes:
        from cryptography.exceptions import InvalidSignature

        from opentine._signing_keys import SignatureError

        signature = bytes(self.signer.sign(bytes(message)))
        try:  # a backend that signs with another key must never pass silently
            self.public_key().verify(signature, bytes(message))
        except (InvalidSignature, ValueError) as exc:
            raise SignatureError("the signer returned a signature its key does not verify") from exc
        return signature


def is_uri(value: Any) -> bool:
    """True for ``scheme:...`` with a signer scheme (``C:\\key`` is a path)."""
    if not isinstance(value, str) or ":" not in value:
        return False
    return value.split(":", 1)[0] in SCHEMES


def resolve(uri: str | Path, **options: Any) -> BaseSigner:
    """The signer *uri* names; a bare path is ``file:PATH``."""
    from opentine._signing_keys import SignatureError

    text = str(uri)
    scheme, _, rest = text.partition(":") if is_uri(text) else ("file", "", text)
    if not rest:
        raise SignatureError(f"signer URI {text!r} names no key")
    if scheme == "file":
        from opentine._signing_keys import ed25519_private_from_file

        return LocalSigner(ed25519_private_from_file(rest, signer=False), uri=f"file:{rest}")
    if scheme == "ssh-agent":
        from opentine._signer_ssh import AgentSigner

        return AgentSigner(rest, **options)
    if scheme == "pkcs11":
        from opentine._signer_pkcs11 import Pkcs11Signer

        return Pkcs11Signer(text, **options)
    from opentine._signer_kms import kms_signer

    return kms_signer(rest, **options)


def key_for(uri: str | Path, **options: Any) -> SignerKey:
    return SignerKey(resolve(uri, **options))


__all__ = [
    "SCHEMES",
    "BaseSigner",
    "LocalSigner",
    "Signer",
    "SignerKey",
    "is_uri",
    "key_for",
    "resolve",
]
