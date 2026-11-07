"""ML-DSA-65 signature *verification* (FIPS 204), pure Python, stdlib only.

Verification only: signing needs secret-dependent arithmetic that this module
makes no constant-time claim about, so opentine signs through ``cryptography``
(``opentine._signing_pq``). Verifying needs no secret, so this one copy serves
both the package (when ``cryptography`` lacks ML-DSA) and ``tine-verify.pyz``.

The algorithm numbers below are FIPS 204's. ``verify`` is ML-DSA.Verify
(Algorithm 3: pure, with a context string); ``verify_internal`` is Algorithm 8.
Both are checked against NIST ACVP sigVer vectors in
``tests/test_041_post_quantum.py``. One verification costs about 6 ms on
CPython 3.13 x86-64 (the NTTs and ExpandA dominate); ``cryptography`` takes well under
a millisecond.
"""

from __future__ import annotations

import hashlib

Q = 8380417
N = 256
D = 13
K, L = 6, 5
TAU, LAMBDA = 49, 192
GAMMA1 = 1 << 19
GAMMA2 = (Q - 1) // 32
ETA = 4
BETA = TAU * ETA
OMEGA = 55
C_TILDE_BYTES = LAMBDA // 4
PUBLIC_KEY_BYTES = 32 + 32 * K * 10
SIGNATURE_BYTES = C_TILDE_BYTES + L * 32 * 20 + OMEGA + K
_N_INV = 8347681  # 256^-1 mod q


def _brv8(value: int) -> int:
    return int(f"{value:08b}"[::-1], 2)


_ZETAS = [pow(1753, _brv8(k), Q) for k in range(N)]


def _ntt(poly: list[int]) -> list[int]:  # Algorithm 41
    w = list(poly)
    m, length = 0, 128
    while length >= 1:
        for start in range(0, N, 2 * length):
            m += 1
            zeta = _ZETAS[m]
            for j in range(start, start + length):
                t = zeta * w[j + length] % Q
                w[j + length] = (w[j] - t) % Q
                w[j] = (w[j] + t) % Q
        length //= 2
    return w


def _ntt_inv(poly: list[int]) -> list[int]:  # Algorithm 42
    w = list(poly)
    m, length = N, 1
    while length < N:
        for start in range(0, N, 2 * length):
            m -= 1
            zeta = Q - _ZETAS[m]
            for j in range(start, start + length):
                t = w[j]
                w[j] = (t + w[j + length]) % Q
                w[j + length] = zeta * (t - w[j + length]) % Q
        length *= 2
    return [x * _N_INV % Q for x in w]


def _unpack(data: bytes, bits: int) -> list[int]:
    """Little-endian bit unpacking of N coefficients (SimpleBitUnpack)."""
    value, mask = int.from_bytes(data, "little"), (1 << bits) - 1
    return [(value >> (i * bits)) & mask for i in range(N)]


def _rej_ntt_poly(seed: bytes) -> list[int]:  # Algorithm 30
    out: list[int] = []
    size = 168 * 5
    while True:
        stream = hashlib.shake_128(seed).digest(size)
        out = []
        for i in range(0, size - 2, 3):
            coeff = stream[i] | stream[i + 1] << 8 | (stream[i + 2] & 0x7F) << 16
            if coeff < Q:
                out.append(coeff)
                if len(out) == N:
                    return out
        size *= 2


def _sample_in_ball(c_tilde: bytes) -> list[int]:  # Algorithm 29
    size = 8 + 4 * TAU + 136
    while True:
        stream = hashlib.shake_256(c_tilde).digest(size)
        signs = int.from_bytes(stream[:8], "little")
        c, pos = [0] * N, 8
        try:
            for i in range(N - TAU, N):
                j = stream[pos]
                pos += 1
                while j > i:
                    j = stream[pos]
                    pos += 1
                c[i] = c[j]
                c[j] = Q - 1 if (signs >> (i + TAU - N)) & 1 else 1
            return c
        except IndexError:
            size *= 2


def _hint_unpack(y: bytes) -> list[list[int]] | None:  # Algorithm 21
    hints = [[0] * N for _ in range(K)]
    index = 0
    for i in range(K):
        end = y[OMEGA + i]
        if end < index or end > OMEGA:
            return None
        first = index
        while index < end:
            if index > first and y[index - 1] >= y[index]:
                return None
            hints[i][y[index]] = 1
            index += 1
    if any(y[index:OMEGA]):
        return None
    return hints


def _use_hint(hint: int, r: int) -> int:  # Algorithms 36 and 40, m = 16
    r0 = r % (2 * GAMMA2)
    if r0 > GAMMA2:
        r0 -= 2 * GAMMA2
    if r - r0 == Q - 1:
        r1, r0 = 0, r0 - 1
    else:
        r1 = (r - r0) // (2 * GAMMA2)
    if not hint:
        return r1
    return (r1 + 1) % 16 if r0 > 0 else (r1 - 1) % 16


def verify_internal(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """FIPS 204 Algorithm 8 over the already-formatted message M'."""
    if len(public_key) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES:
        return False
    rho = public_key[:32]
    t1 = [_unpack(public_key[32 + 320 * i : 352 + 320 * i], 10) for i in range(K)]
    c_tilde = signature[:C_TILDE_BYTES]
    body = signature[C_TILDE_BYTES : C_TILDE_BYTES + L * 640]
    z = [[GAMMA1 - x for x in _unpack(body[640 * i : 640 * (i + 1)], 20)] for i in range(L)]
    hints = _hint_unpack(signature[C_TILDE_BYTES + L * 640 :])
    if hints is None or max(abs(x) for poly in z for x in poly) >= GAMMA1 - BETA:
        return False
    tr = hashlib.shake_256(public_key).digest(64)
    mu = hashlib.shake_256(tr + message).digest(64)
    c_hat = _ntt(_sample_in_ball(c_tilde))
    z_hat = [_ntt([x % Q for x in poly]) for poly in z]
    w1 = bytearray()
    for r in range(K):
        acc = [0] * N
        for s in range(L):
            a_hat = _rej_ntt_poly(rho + bytes((s, r)))
            zs = z_hat[s]
            acc = [(acc[i] + a_hat[i] * zs[i]) % Q for i in range(N)]
        t_hat = _ntt([x << D for x in t1[r]])
        w = _ntt_inv([(acc[i] - c_hat[i] * t_hat[i]) % Q for i in range(N)])
        packed = sum(_use_hint(h, x) << (4 * i) for i, (h, x) in enumerate(zip(hints[r], w)))
        w1 += packed.to_bytes(128, "little")
    return hashlib.shake_256(mu + bytes(w1)).digest(C_TILDE_BYTES) == c_tilde


def verify(public_key: bytes, message: bytes, signature: bytes, context: bytes = b"") -> bool:
    """FIPS 204 Algorithm 3: pure ML-DSA-65 with a context string of at most 255 bytes."""
    if len(context) > 255:
        return False
    return verify_internal(public_key, bytes((0, len(context))) + context + message, signature)


__all__ = ["PUBLIC_KEY_BYTES", "SIGNATURE_BYTES", "verify", "verify_internal"]
