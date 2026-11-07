"""Post-quantum ``tine-sig/3`` blocks in the stdlib verifier (SPEC 4.6.1).

The same rules as ``opentine._signing_pq.pq_verdict``: ``ml-dsa-65`` is a pure
FIPS 204 signature with an empty context; ``ed25519+ml-dsa-65`` concatenates
an Ed25519 and an ML-DSA-65 signature (and key) and verifies only when both
halves do, the ML-DSA half under ``COMPOSITE_CONTEXT``.
"""

from __future__ import annotations

from typing import Any

from .._ed25519_order import weak_public_key
from . import _ed25519, _mldsa

COMPOSITE_CONTEXT = b"opentine.tine-sig/3:ed25519+ml-dsa-65"
#: ``alg -> (value bytes, public key bytes)``.
SIZES = {
    "ml-dsa-65": (_mldsa.SIGNATURE_BYTES, _mldsa.PUBLIC_KEY_BYTES),
    "ed25519+ml-dsa-65": (64 + _mldsa.SIGNATURE_BYTES, 32 + _mldsa.PUBLIC_KEY_BYTES),
}


def _hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 2 * length
        and all(ch in "0123456789abcdef" for ch in value)
    )


def verdict(
    algorithm: str, value: Any, embedded: Any, signed: bytes, public_key: bytes | None
) -> tuple[bool, str, str]:
    value_len, key_len = SIZES[algorithm]
    if not _hex(value, value_len):
        return False, "error", "malformed signature value"
    if not _hex(embedded, key_len):
        return False, "error", f"malformed {algorithm} public key"
    if public_key is None:
        return False, "no-key", f"{algorithm} signature present but no trusted public key"
    if len(public_key) != key_len:
        return False, "mismatch", f"the trusted key is not a {algorithm} key"
    if embedded != public_key.hex():
        return False, "mismatch", "embedded public key is not the trusted key"
    raw = bytes.fromhex(value)
    if algorithm == "ml-dsa-65":
        ok = _mldsa.verify(public_key, signed, raw)
    else:
        if weak_public_key(public_key[:32]):
            return False, "error", "ed25519 public key has small order or a non-canonical encoding"
        ed_ok = _ed25519.verify(public_key[:32], signed, raw[:64])
        ok = _mldsa.verify(public_key[32:], signed, raw[64:], COMPOSITE_CONTEXT) and ed_ok
    if not ok:
        return False, "mismatch", "signature mismatch"
    return True, "verified", "ok"


__all__ = ["SIZES", "verdict"]
