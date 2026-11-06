"""``TINEAES6`` (0.41, roadmap X28): key id, epoch, XAES-256-GCM, optional Padme.

The roadmap calls this format "TINEAES5"; 0.35 had already shipped that magic
for the KMS envelope (``_sealed_envelope``), so X28 is ``TINEAES6`` on disk.

Layout (all integers big-endian)::

    "TINEAES6" | u8 len(key_id) | key_id | u32 epoch | u8 flags | u8 codec
    | u64 size | 24-byte nonce | XAES-256-GCM(body, aad)

``flags`` bit 0 marks Padme padding: the body is then ``u64 len || inner ||
zeros`` up to the Padme size, so the ciphertext length leaks O(log log L) bits.
``inner`` is the ``_codec`` wrapper, as in ``TINEAES4``. The associated data
length-prefixes purpose, tenant, context, key id, epoch, flags, codec and size,
so a ciphertext cannot be moved to another slot, relabelled to another key or
epoch, or have its padding or size flag flipped. The per-tenant key is derived
from the 32-byte master, key id and epoch; XAES-256-GCM's 192-bit random nonce
makes nonce reuse negligible however many objects one key seals.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from opentine.remote import _xaes

SEALED6 = b"TINEAES6"
PADDED = 0x01
_MAX_KEY_ID = 64


def _lp(*parts: bytes) -> bytes:
    return b"".join(len(p).to_bytes(4, "big") + p for p in parts)


def key6(master: bytes, key_id: str, epoch: int, tenant: str) -> bytes:
    info = _lp(key_id.encode(), epoch.to_bytes(4, "big"), tenant.encode())
    return hmac.new(master, b"opentine.tenant-key.v6\0" + info, hashlib.sha256).digest()


def aad6(purpose, tenant, context, key_id, epoch, flags, codec, size) -> bytes:  # noqa: ANN001
    return b"opentine.sealed.v6\0" + _lp(
        purpose.encode(), tenant.encode(), context.encode(), key_id.encode(),
        epoch.to_bytes(4, "big"), bytes([flags, codec]), size.to_bytes(8, "big"),
    )  # fmt: skip


def parse_header(ciphertext: bytes) -> tuple[str, int, int, int, int, int]:
    """``(key_id, epoch, flags, codec, size, header_length)`` of a TINEAES6 file."""
    if not ciphertext.startswith(SEALED6) or len(ciphertext) < len(SEALED6) + 1:
        raise ValueError("invalid encrypted object header")
    at = len(SEALED6) + 1
    end = at + ciphertext[len(SEALED6)]
    if end + 14 + _xaes.NONCE_SIZE + 16 > len(ciphertext) or end == at:
        raise ValueError("invalid encrypted object header")
    key_id = ciphertext[at:end].decode("ascii", "strict")
    epoch = int.from_bytes(ciphertext[end : end + 4], "big")
    flags, codec = ciphertext[end + 4], ciphertext[end + 5]
    size = int.from_bytes(ciphertext[end + 6 : end + 14], "big")
    if flags & ~PADDED:
        raise ValueError("encrypted object has unknown flags")
    return key_id, epoch, flags, codec, size, end + 14


def seal6(
    master: bytes, key_id: str, epoch: int, purpose: str, tenant: str, context: str,
    plaintext: bytes, codec: str | None, *, pad: bool = False,
) -> bytes:  # fmt: skip
    from opentine import _codec

    raw_id = key_id.encode("ascii")
    if not 0 < len(raw_id) <= _MAX_KEY_ID or not 0 <= epoch < 2**32:
        raise ValueError("TINEAES6 needs a 1-64 byte ASCII key id and a u32 epoch")
    inner = _codec.wrap(plaintext, codec) if codec else None
    inner = inner or _codec.wrap(plaintext, "raw", force=True)
    assert inner is not None
    codec_byte, flags = inner[len(_codec.MAGIC)], PADDED if pad else 0
    if pad:
        body = len(inner).to_bytes(8, "big") + inner
        inner = body + bytes(_xaes.padme(len(body)) - len(body))
    header = SEALED6 + bytes([len(raw_id)]) + raw_id + epoch.to_bytes(4, "big")
    header += bytes([flags, codec_byte]) + len(plaintext).to_bytes(8, "big")
    nonce = os.urandom(_xaes.NONCE_SIZE)
    associated = aad6(purpose, tenant, context, key_id, epoch, flags, codec_byte, len(plaintext))
    key = key6(master, key_id, epoch, tenant)
    return header + nonce + _xaes.encrypt(key, nonce, inner, associated)


def unseal6(
    keyring: dict[tuple[str, int], bytes], purpose: str, tenant: str, context: str,
    ciphertext: bytes, *, limit: int,
) -> bytes:  # fmt: skip
    from opentine import _codec

    key_id, epoch, flags, codec_byte, size, at = parse_header(ciphertext)
    if size > limit:
        raise ValueError("encrypted object declares more bytes than the reader allows")
    master = keyring.get((key_id, epoch))
    if master is None:
        raise ValueError(f"no master key for key id {key_id!r} epoch {epoch}")
    nonce, body = ciphertext[at : at + _xaes.NONCE_SIZE], ciphertext[at + _xaes.NONCE_SIZE :]
    associated = aad6(purpose, tenant, context, key_id, epoch, flags, codec_byte, size)
    inner = _xaes.decrypt(key6(master, key_id, epoch, tenant), nonce, body, associated)
    if flags & PADDED:
        length = int.from_bytes(inner[:8], "big")
        if length > len(inner) - 8 or any(inner[8 + length :]):
            raise ValueError("encrypted object padding is invalid")
        inner = inner[8 : 8 + length]
    if (
        not _codec.is_wrapped(inner)
        or inner[len(_codec.MAGIC)] != codec_byte
        or _codec.declared_size(inner) != size
    ):
        raise ValueError("encrypted object does not match its header")
    try:
        return _codec.unwrap(inner, limit=size)
    except _codec.CodecError as exc:
        raise ValueError("encrypted object body is corrupt") from exc
