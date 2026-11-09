"""ECDSA P-256 / SHA-256 signature verification in pure Python, verify only.

Written after FIPS 186-5 §6.4.2 (ECDSA signature verification) with the curve
of SP 800-186 §3.2.1.3 (P-256). Public keys are SEC 1 §2.3.3 uncompressed
points (``04 || X || Y``) or the fixed SubjectPublicKeyInfo DER/PEM wrapping of
one (RFC 5480); signatures are DER ``Ecdsa-Sig-Value`` (RFC 3279 §2.2.3), as
OpenSSL and Sigstore write them. High-S signatures verify, as in OpenSSL.
Every input is public, so constant-time arithmetic is not needed.

Used by the OMS model-signature check (``opentine._oms``, SPEC 4.26) and its
independent port for ``tine-verify.pyz`` (``_pyz._oms``).
"""

from __future__ import annotations

import base64
import hashlib
import re

P = 2**256 - 2**224 + 2**192 + 2**96 - 1
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
#: The DER prefix of a P-256 SubjectPublicKeyInfo (id-ecPublicKey, prime256v1).
SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")

Point = tuple[int, int] | None


def _add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % P == 0:
            return None
        slope = (3 * p[0] * p[0] + A) * pow(2 * p[1], -1, P) % P
    else:
        slope = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (slope * slope - p[0] - q[0]) % P
    return x, (slope * (p[0] - x) - p[1]) % P


def multiply(k: int, point: Point) -> Point:
    out: Point = None
    while k:
        if k & 1:
            out = _add(out, point)
        point = _add(point, point)
        k >>= 1
    return out


def point(public: bytes) -> tuple[int, int]:
    """A SEC 1 uncompressed point on P-256; ``ValueError`` otherwise."""
    if len(public) != 65 or public[0] != 4:
        raise ValueError("P-256 public key is not a 65-byte uncompressed point")
    x, y = int.from_bytes(public[1:33], "big"), int.from_bytes(public[33:], "big")
    if x >= P or y >= P or (y * y - (x * x * x + A * x + B)) % P:
        raise ValueError("P-256 public key is not on the curve")
    return x, y


def public_key(data: bytes | str) -> bytes:
    """The 65-byte point from raw bytes, hex, SPKI DER or a PEM ``PUBLIC KEY``."""
    if isinstance(data, str):
        text = data.strip()
        if re.fullmatch(r"[0-9a-fA-F]{130}", text):
            return bytes.fromhex(text)
        data = text.encode("ascii", "replace")
    pem = re.search(rb"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----", data, re.S)
    if pem:
        data = base64.b64decode(b"".join(pem.group(1).split()), validate=True)
    if data.startswith(SPKI_PREFIX) and len(data) == len(SPKI_PREFIX) + 65:
        data = data[len(SPKI_PREFIX) :]
    point(data)
    return data


def _der_int(data: bytes, at: int) -> tuple[int, int]:
    if at + 2 > len(data) or data[at] != 2 or data[at + 1] == 0 or data[at + 1] > 33:
        raise ValueError("bad DER INTEGER")
    length, at = data[at + 1], at + 2
    body = data[at : at + length]
    if len(body) != length or body[0] & 0x80 or (length > 1 and body[0] == 0 and body[1] < 0x80):
        raise ValueError("non-minimal or negative DER INTEGER")
    return int.from_bytes(body, "big"), at + length


def decode_signature(der: bytes) -> tuple[int, int]:
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("signature is not a DER SEQUENCE")
    r, at = _der_int(der, 2)
    s, at = _der_int(der, at)
    if at != len(der):
        raise ValueError("trailing bytes after the DER signature")
    return r, s


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """FIPS 186-5 ECDSA verify with SHA-256; any malformed input is ``False``."""
    try:
        q = point(public)
        r, s = decode_signature(signature)
    except ValueError:
        return False
    if not (0 < r < N and 0 < s < N):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, N)
    found = _add(multiply(e * w % N, G), multiply(r * w % N, q))
    return found is not None and found[0] % N == r


__all__ = ["N", "G", "decode_signature", "multiply", "point", "public_key", "verify"]
