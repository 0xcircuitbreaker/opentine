"""Key loading and optional Ed25519 implementation details."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from opentine._ed25519_order import weak_public_key

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    HAS_ED25519 = True
except Exception:  # pragma: no cover
    Ed25519PrivateKey = None  # type: ignore[assignment,misc]
    Ed25519PublicKey = None  # type: ignore[assignment,misc]
    HAS_ED25519 = False


class SignatureError(Exception):
    pass


MAX_SIGNING_KEY_BYTES = 1024 * 1024


def is_hex(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return len(value) % 2 == 0


def hmac_key_from_env(name: str) -> bytes:
    value = os.environ.get(name)
    if value is None:
        raise SignatureError(f"environment variable {name!r} is not set")
    return value.encode()


def hmac_key_from_file(path: str | Path) -> bytes:
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_SIGNING_KEY_BYTES + 1)
    if len(raw) > MAX_SIGNING_KEY_BYTES:
        raise SignatureError("signing key file exceeds the 1 MiB limit")
    return raw[:-1] if raw.endswith(b"\n") else raw


def _require_crypto() -> None:
    if not HAS_ED25519:
        raise SignatureError("ed25519 support requires: pip install 'opentine[crypto]'")


def load_ed25519_private(key: Any):
    _require_crypto()
    if isinstance(key, Ed25519PrivateKey) or type(key).__name__ == "SignerKey":
        return key
    if isinstance(key, str):
        key = key.strip()
        if is_hex(key) and len(key) == 64:
            return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key))
        key = key.encode()
    if isinstance(key, (bytes, bytearray)):
        if len(key) == 32:
            return Ed25519PrivateKey.from_private_bytes(bytes(key))
        text = bytes(key).strip()
        if len(text) == 64 and is_hex(text.decode(errors="ignore")):
            return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(text.decode()))
    raise SignatureError("ed25519 private key must be a 32-byte seed or 64-char hex")


def coerce_ed25519_public(key: Any):
    """A trusted Ed25519 public key, refusing one no honest signer could hold.

    A small-order or non-canonically encoded key verifies a crafted signature
    over any message (``_ed25519_order``), so it is never a key to trust.
    """
    _require_crypto()
    if isinstance(key, Ed25519PublicKey):
        public = key
    elif isinstance(key, str) and is_hex(key.strip()) and len(key.strip()) == 64:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.strip()))
    elif isinstance(key, (str, bytes, bytearray)) and len(raw := _raw(key)) == 32:
        public = Ed25519PublicKey.from_public_bytes(raw)
    else:
        raise SignatureError("ed25519 public key must be a 32-byte key or 64-char hex")
    if weak_public_key(public.public_bytes_raw()):
        raise SignatureError("ed25519 public key has small order or a non-canonical encoding")
    return public


def _raw(key: str | bytes | bytearray) -> bytes:
    return key.strip().encode() if isinstance(key, str) else bytes(key)


def ed25519_private_from_file(path: str | Path, *, signer: bool = True, legacy_warn: bool = True):
    """The signing key a path or signer URI names (``_signer``).

    With *signer* (the default) the result is a ``SignerKey``; an encrypted
    PKCS#8 file asks ``_key_store`` for its passphrase, and a 0.40 plaintext-hex
    seed still loads, with a ``PlaintextKeyWarning`` unless *legacy_warn* is off.
    """
    from opentine import _key_store, _signer

    if _signer.is_uri(str(path)) and not str(path).startswith("file:"):
        if not signer:
            raise SignatureError(f"{path} is not a key file")
        return _signer.key_for(path)
    path = str(path)[5:] if str(path).startswith("file:") else path
    raw = hmac_key_from_file(path)
    if _key_store.is_pem(raw):
        private = _key_store.load_pem(raw, str(path))
    else:
        try:
            private = load_ed25519_private(raw.decode())
        except UnicodeDecodeError:
            private = load_ed25519_private(raw)
        if legacy_warn and len(raw.strip()) == 64:
            _key_store.warn_plaintext(str(path))
    return _signer.SignerKey(_signer.LocalSigner(private, f"file:{path}")) if signer else private


def ed25519_public_from_file(path: str | Path):
    raw = hmac_key_from_file(path)
    try:
        return coerce_ed25519_public(raw.decode())
    except UnicodeDecodeError:
        return coerce_ed25519_public(raw)


def generate_ed25519() -> tuple[str, str]:
    _require_crypto()
    private = Ed25519PrivateKey.generate()
    return private.private_bytes_raw().hex(), private.public_key().public_bytes_raw().hex()
