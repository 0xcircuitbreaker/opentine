"""XAES-256-GCM (C2SP, https://c2sp.org/XAES-256-GCM) and Padme length padding.

XAES-256-GCM extends AES-256-GCM to a 192-bit nonce, so a random nonce per
message is safe for any practical number of messages under one key. The first
12 nonce bytes derive a per-message AES-256 key from the master with the NIST
SP 800-108r1 counter KDF over AES-256-CMAC (computed directly from AES-ECB,
as the spec describes); the last 12 bytes are the AES-256-GCM nonce. Every
primitive is FIPS-approved AES, so XAES-256-GCM is usable in ``--fips`` mode.
"""

from __future__ import annotations

NONCE_SIZE = 24
KEY_SIZE = 32


def _aes_block(key: bytes, block: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def derive_key(key: bytes, nonce: bytes) -> bytes:
    """The per-message AES-256-GCM key for the first 12 bytes of *nonce*."""
    if len(key) != KEY_SIZE:
        raise ValueError("XAES-256-GCM needs a 32-byte key")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("XAES-256-GCM needs a 24-byte nonce")
    lval = int.from_bytes(_aes_block(key, bytes(16)), "big")
    k1 = (lval << 1) & ((1 << 128) - 1)
    if lval >> 127:
        k1 ^= 0x87
    k1b = k1.to_bytes(16, "big")
    blocks = (b"\x00\x01X\x00" + nonce[:12], b"\x00\x02X\x00" + nonce[:12])
    return b"".join(_aes_block(key, bytes(a ^ b for a, b in zip(m, k1b))) for m in blocks)


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, associated: bytes | None) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(derive_key(key, nonce)).encrypt(nonce[12:], plaintext, associated)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated: bytes | None) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(derive_key(key, nonce)).decrypt(nonce[12:], ciphertext, associated)


def padme(length: int) -> int:
    """Padme (PURBs, Nikitin et al. 2019): the padded size, at most ~12% larger.

    It leaks O(log log L) bits of the length instead of all of it."""
    if length < 2:
        return length
    e = length.bit_length() - 1  # floor(log2 L)
    s = e.bit_length()  # floor(log2 e) + 1
    mask = (1 << (e - s)) - 1 if e > s else 0
    return (length + mask) & ~mask
