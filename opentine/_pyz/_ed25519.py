"""Ed25519 signature verification in pure Python (RFC 8032 §5.1.7), verify only.

Written after the RFC's reference code: points in extended twisted-Edwards
coordinates (§5.1.4), decoding per §5.1.3 and the cofactorless check
``encode([S]B - [k]A) == R`` that OpenSSL (and so ``cryptography``) performs.
``S`` must be below the group order ``L``; ``A`` must decode; ``R`` is compared
as bytes, so a non-canonical ``R`` never verifies. No secret is ever handled,
so constant-time arithmetic is not needed: every input here is public.

Checked against the RFC 8032 §7.1 vectors and Wycheproof's ``ed25519_test``
(``tests/test_039_pyz_verifier.py``).
"""

from __future__ import annotations

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple[int, int, int, int]
IDENTITY: Point = (0, 1, 1, 0)


def _add(p: Point, q: Point) -> Point:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(scalar: int, point: Point) -> Point:
    result = IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _negate(point: Point) -> Point:
    x, y, z, t = point
    return ((P - x) % P, y, z, (P - t) % P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    return P - x if (x & 1) != sign else x


def decode_point(raw: bytes) -> Point | None:
    """The point *raw* encodes, or ``None`` (wrong length, ``y >= p``, off the curve)."""
    if len(raw) != 32:
        return None
    value = int.from_bytes(raw, "little")
    y, sign = value & ((1 << 255) - 1), value >> 255
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def encode_point(point: Point) -> bytes:
    x, y, z, _ = point
    inverse = pow(z, P - 2, P)
    x, y = x * inverse % P, y * inverse % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_BY = 4 * pow(5, P - 2, P) % P
_BX = _recover_x(_BY, 0)
if _BX is None:  # pragma: no cover - the base point always decodes
    raise RuntimeError("Ed25519 base point")
BASE: Point = (_BX, _BY, 1, _BX * _BY % P)


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Whether *signature* is a valid Ed25519 signature by *public* over *message*."""
    if len(public) != 32 or len(signature) != 64:
        return False
    point = decode_point(public)
    if point is None:
        return False
    encoded_r, s = signature[:32], int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % L
    check = _add(_mul(s, BASE), _negate(_mul(k, point)))
    return encode_point(check) == encoded_r


__all__ = ["decode_point", "encode_point", "verify"]
