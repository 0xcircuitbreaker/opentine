"""Key loading and optional Ed25519 implementation details."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

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
    raw = Path(path).read_bytes()
    return raw[:-1] if raw.endswith(b"\n") else raw


def _require_crypto() -> None:
    if not HAS_ED25519:
        raise SignatureError("ed25519 support requires: pip install 'opentine[crypto]'")


def load_ed25519_private(key: Any):
    _require_crypto()
    if isinstance(key, Ed25519PrivateKey):
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
    _require_crypto()
    if isinstance(key, Ed25519PublicKey):
        return key
    if isinstance(key, str):
        key = key.strip()
        if is_hex(key) and len(key) == 64:
            return Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
        key = key.encode()
    if isinstance(key, (bytes, bytearray)) and len(key) == 32:
        return Ed25519PublicKey.from_public_bytes(bytes(key))
    raise SignatureError("ed25519 public key must be a 32-byte key or 64-char hex")


def ed25519_private_from_file(path: str | Path):
    raw = hmac_key_from_file(path)
    try:
        return load_ed25519_private(raw.decode())
    except UnicodeDecodeError:
        return load_ed25519_private(raw)


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
