"""Ed25519 public keys no honest signer has: small order, or a non-canonical spelling.

OpenSSL verifies Ed25519 without a cofactor check and loads any 32 bytes as a
key, so a public key of small order -- the identity point ``01 00..00`` among
the eight -- verifies one crafted signature (``R`` = that point, ``S`` = 0) over
*every* message. A trust-on-first-use check takes its key from the signature
block, so such a block "verified" anything. No generated key has small order (a
clamped secret is a multiple of 8 times a prime-order base point), and none is
written non-canonically (``y >= p``), so both are refused wherever a key is
trusted. Pure integer arithmetic over the RFC 8032 curve; no dependency.
"""

from __future__ import annotations

_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1)


def _decode(raw: bytes) -> tuple[int, int] | None:
    """The affine point *raw* encodes (RFC 8032 §5.1.3), or ``None`` if off the curve."""
    value = int.from_bytes(raw, "little")
    sign, y = value >> 255, value & ((1 << 255) - 1)
    u, v = (y * y - 1) % _P, (_D * y * y + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P
    if v * x * x % _P == -u % _P:
        x = x * _SQRT_M1 % _P
    elif v * x * x % _P != u:
        return None
    # x = 0 with the sign bit set is invalid under RFC 8032, but OpenSSL reads it
    # as (0, y) -- the identity or the order-2 point -- so it is decoded as such.
    return ((_P - x) % _P if x & 1 != sign else x), y


def _double(point: tuple[int, int]) -> tuple[int, int]:
    # The complete twisted-Edwards addition law (a = -1), applied to point + point.
    x, y = point
    t = _D * x * x * y * y % _P
    return (
        2 * x * y * pow((1 + t) % _P, _P - 2, _P) % _P,
        (y * y + x * x) * pow((1 - t) % _P, _P - 2, _P) % _P,
    )


def weak_public_key(raw: bytes) -> bool:
    """True for a 32-byte encoding that is non-canonical or of small order.

    An encoding off the curve is left to the verifier (it can verify nothing),
    so this only ever refuses what would otherwise *pass*.
    """
    if len(raw) != 32:
        return True
    if int.from_bytes(raw, "little") & ((1 << 255) - 1) >= _P:
        return True  # y >= p: a second spelling of a point, never written honestly
    point = _decode(raw)
    if point is None:
        return False
    for _ in range(3):
        point = _double(point)
    return point == _IDENTITY


__all__ = ["weak_public_key"]
