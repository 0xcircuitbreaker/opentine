"""The five fixed, published test keys. Never a real key; never rotated."""

from __future__ import annotations

#: SPEC 4.5's own worked-vector key: the 32 ASCII bytes of this hex string.
HMAC_A = b"0123456789abcdef0123456789abcdef"
#: A second, different 32-byte key, so ``mismatch`` is a key disagreement.
HMAC_B = b"fedcba9876543210fedcba9876543210"
#: Exactly ``MIN_HMAC_KEY_BYTES``; must verify.
HMAC_FLOOR = b"0123456789abcdef"
#: Exactly one byte below the floor; must produce state ``error``.
HMAC_SHORT = b"0123456789abcde"
#: bytes(range(32)). Ed25519 is deterministic (RFC 8032), so its value is stable.
ED25519_SEED = bytes(range(32))
#: The key every golden compat fixture was signed with by the real published
#: release. Published in tests/test_backwards_compat.py since 0.3.0; it is here
#: so the compat family is runnable without reading Python.
HMAC_COMPAT = b"compat-golden-signing-key-000001"

KEYS = {
    "hmac_a": HMAC_A,
    "hmac_b": HMAC_B,
    "hmac_floor": HMAC_FLOOR,
    "hmac_short": HMAC_SHORT,
    "ed25519_seed": ED25519_SEED,
    "hmac_compat": HMAC_COMPAT,
}
