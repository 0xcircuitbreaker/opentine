"""Ed25519 private keys at rest (0.41, X24): encrypted PKCS#8, not plaintext hex.

A new key file is a PEM ``ENCRYPTED PRIVATE KEY`` (PKCS#8, PBES2 with AES-256,
``cryptography``'s ``BestAvailableEncryption``). The passphrase comes from, in
order:

1. ``OPENTINE_KEY_PASSPHRASE``;
2. the OS keyring, when ``OPENTINE_KEY_KEYRING=1`` and the optional ``keyring``
   package is installed (``pip install 'opentine[keyring]'``); a new key with no
   stored passphrase gets a random one, saved there;
3. a prompt, only when stdin is a terminal.

With none of them a new key is refused unless the caller asked for a legacy
plaintext key. A 0.40-and-earlier plaintext-hex seed still loads, with a
:class:`PlaintextKeyWarning`; ``tine key encrypt PATH`` rewrites one in place.
"""

from __future__ import annotations

import os
import secrets
import sys
import warnings
from pathlib import Path
from typing import Any

PASSPHRASE_ENV = "OPENTINE_KEY_PASSPHRASE"
KEYRING_ENV = "OPENTINE_KEY_KEYRING"
KEYRING_SERVICE = "opentine"
KEYRING_USER = "key-passphrase"
PEM_ENCRYPTED = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
PEM_PLAIN = b"-----BEGIN PRIVATE KEY-----"


class PlaintextKeyWarning(FutureWarning):
    """A private key stored as plaintext hex (deprecated in 0.41)."""


class PassphraseUnavailable(Exception):
    """No passphrase source is available for an encrypted key."""


def _keyring(create: bool) -> bytes | None:
    if os.environ.get(KEYRING_ENV, "") not in ("1", "true", "yes"):
        return None
    try:
        import keyring  # optional extra
    except ImportError:
        return None
    try:
        stored = keyring.get_password(KEYRING_SERVICE, KEYRING_USER)
        if stored is None and create:
            stored = secrets.token_urlsafe(32)
            keyring.set_password(KEYRING_SERVICE, KEYRING_USER, stored)
    except Exception:  # noqa: BLE001 - a keyring with no backend is simply absent
        return None
    return stored.encode() if stored else None


def _prompt(label: str, confirm: bool) -> bytes | None:
    try:
        interactive = sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):
        interactive = False
    if not interactive:
        return None
    import getpass

    first = getpass.getpass(f"Passphrase for {label}: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != first:
        raise PassphraseUnavailable("the passphrases did not match")
    return first.encode() if first else None


def passphrase(label: str = "the key", *, create: bool = False) -> bytes:
    """The key passphrase from the env, the keyring or a prompt; never empty."""
    value = os.environ.get(PASSPHRASE_ENV)
    if value:
        return value.encode()
    found = _keyring(create) or _prompt(label, confirm=create)
    if not found:
        raise PassphraseUnavailable(
            f"no passphrase for {label}: set {PASSPHRASE_ENV}, enable the OS keyring "
            f"({KEYRING_ENV}=1 with 'opentine[keyring]'), or run interactively"
        )
    return found


def encrypted_pem(private: Any, secret: bytes) -> bytes:
    """*private* as an encrypted PKCS#8 PEM under *secret*."""
    from cryptography.hazmat.primitives import serialization

    return private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(secret),
    )


def is_pem(raw: bytes) -> bool:
    head = raw.lstrip()[:40]
    return head.startswith(PEM_ENCRYPTED) or head.startswith(PEM_PLAIN)


def load_pem(raw: bytes, label: str = "the key") -> Any:
    """The Ed25519 key in a PKCS#8 PEM; asks for a passphrase only when encrypted."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine._signing_keys import SignatureError

    secret = None
    if raw.lstrip().startswith(PEM_ENCRYPTED):
        try:
            secret = passphrase(label)
        except PassphraseUnavailable as exc:
            raise SignatureError(str(exc)) from exc
    try:
        key = serialization.load_pem_private_key(raw, password=secret)
    except (TypeError, ValueError) as exc:
        raise SignatureError(f"cannot decrypt {label}: wrong passphrase or damaged key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError(f"{label} is not an Ed25519 private key")
    return key


def warn_plaintext(label: str) -> None:
    warnings.warn(
        f"{label} is a plaintext-hex private key (deprecated since 0.41); "
        f"encrypt it with: tine key encrypt {label}",
        PlaintextKeyWarning,
        stacklevel=3,
    )


def write_private(path: str | Path, private: Any, *, plaintext: bool = False) -> str:
    """Write *private* to *path* (0600); ``"encrypted"`` or ``"plaintext"``."""
    from opentine._canon import atomic_write_text

    if plaintext:
        seed = private.private_bytes_raw().hex()
        atomic_write_text(path, seed + "\n", fsync=True, mode=0o600)
        return "plaintext"
    secret = passphrase(str(path), create=True)
    atomic_write_text(path, encrypted_pem(private, secret).decode("ascii"), fsync=True, mode=0o600)
    return "encrypted"


def encrypt_file(path: str | Path) -> bool:
    """Rewrite the key at *path* as encrypted PKCS#8; False when it already was."""
    from opentine._signing_keys import ed25519_private_from_file, hmac_key_from_file

    raw = hmac_key_from_file(path)
    if raw.lstrip().startswith(PEM_ENCRYPTED):
        return False
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", PlaintextKeyWarning)
        private = ed25519_private_from_file(path, signer=False)
    write_private(path, private)
    return True


__all__ = [
    "KEYRING_ENV",
    "PASSPHRASE_ENV",
    "PassphraseUnavailable",
    "PlaintextKeyWarning",
    "encrypt_file",
    "encrypted_pem",
    "is_pem",
    "load_pem",
    "passphrase",
    "warn_plaintext",
    "write_private",
]
