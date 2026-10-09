"""How the CLI reads key material: refusals and warnings around the raw loaders.

The library loaders (``_signing_keys``) read bytes; these wrap them for every
verb that takes ``--key-env`` / ``--key-file`` / ``--ed25519-key-file``:

* **A public key is never an HMAC secret.** Handing ``--key-file`` an Ed25519
  public key -- the easy mistake, next to ``--pubkey`` -- made the *public* key
  the shared secret, so anyone could mint HMAC blocks that verified. A PEM or
  OpenSSH public key, or any file named ``*.pub``, is refused as HMAC material.
* **A guessable HMAC key is announced.** The 16-byte floor is length only, so
  ``passwordpassword`` passed, and every signed object is an offline oracle for
  guessing it. A key whose estimated strength is under 128 bits warns on stderr;
  ``tine keygen --hmac`` makes a strong one.
* **A private key file others can read is announced**, the way ssh does (POSIX).

Warnings go to stderr, so ``--json`` output is untouched.
"""

from __future__ import annotations

import math
import os
import stat
import sys
from pathlib import Path

from opentine._cli_text import plain_text
from opentine._signing_keys import (
    SignatureError,
    ed25519_private_from_file,
    hmac_key_from_env,
    hmac_key_from_file,
)

#: Estimated strength under which an HMAC key is called guessable.
STRONG_KEY_BITS = 128
_PUBLIC_MARKERS = (b"-----BEGIN PUBLIC KEY-----", b"ssh-ed25519 ", b"-----BEGIN SSH2 PUBLIC KEY")


def _warn(message: str) -> None:
    print(f"tine: warning: {message}", file=sys.stderr)


_DIGITS = frozenset(b"0123456789")
_LOWER = frozenset(b"abcdefghijklmnopqrstuvwxyz")
_HEX = _DIGITS | frozenset(b"abcdefABCDEF")
_ALNUM = _DIGITS | _LOWER | frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_ALPHABETS = (
    (10, _DIGITS),
    (16, _HEX),
    (26, _LOWER),
    (36, _DIGITS | _LOWER),
    (62, _ALNUM),
    (66, _ALNUM | frozenset(b"+/=-_")),
    (95, frozenset(range(0x20, 0x7F))),
)


def estimated_bits(key: bytes) -> float:
    """A deliberately crude ceiling on a key's strength, deterministic and cheap.

    Length times the bits per symbol of the smallest common alphabet the key
    fits (digits, hex, lower case, alphanumeric, base64, printable, bytes),
    capped by 16 bits per distinct symbol so a repeated pattern cannot pass.
    """
    used = frozenset(key)
    size = next((size for size, alphabet in _ALPHABETS if used <= alphabet), 256)
    return min(len(key) * math.log2(size), len(used) * 16.0)


def warn_weak_hmac(key: bytes, source: str) -> None:
    if estimated_bits(key) < STRONG_KEY_BITS:
        _warn(
            f"the HMAC key from {plain_text(source)} looks guessable (about "
            f"{estimated_bits(key):.0f} bits); make one with `tine keygen --hmac --out FILE`"
        )


def warn_exposed(path: str | Path) -> None:
    """ssh's check: a secret key file must not be readable by group or others."""
    if os.name != "posix":
        return
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return  # the loader reports an unreadable file itself
    if mode & 0o077:
        _warn(
            f"key file {plain_text(path)} is readable by others (mode {mode:04o}); "
            f"run `chmod 600 {plain_text(path)}`"
        )


def refuse_public_key(raw: bytes, path: str | Path | None = None) -> None:
    named_public = path is not None and Path(path).suffix.lower() == ".pub"
    if named_public or any(marker in raw[:4096] for marker in _PUBLIC_MARKERS):
        raise SignatureError(
            f"{plain_text(path) if path else 'the key'} is a public key, and an HMAC key "
            "must be secret; check an Ed25519 signature with --pubkey instead"
        )


def hmac_key(key_env: str | None = None, key_file: str | None = None) -> bytes:
    """The HMAC key a verb's ``--key-env`` or ``--key-file`` names, checked."""
    if key_file:
        warn_exposed(key_file)
        key = hmac_key_from_file(key_file)
        refuse_public_key(key, key_file)
        warn_weak_hmac(key, key_file)
        return key
    if not key_env:
        raise SignatureError("no HMAC key flag given")
    key = hmac_key_from_env(key_env)
    refuse_public_key(key)
    warn_weak_hmac(key, f"${key_env}")
    return key


def ed25519_private(path: str) -> object:
    warn_exposed(path)
    return ed25519_private_from_file(path)


__all__ = [
    "STRONG_KEY_BITS",
    "ed25519_private",
    "estimated_bits",
    "hmac_key",
    "refuse_public_key",
    "warn_exposed",
    "warn_weak_hmac",
]
