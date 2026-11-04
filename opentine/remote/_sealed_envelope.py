"""``TINEAES5``: slot-bound envelope sealing for KMS key providers (0.35)."""

from __future__ import annotations

import os
import struct
from typing import Any

from opentine.remote._sealed import SEALED5

#: ``TINEAES5`` (0.35): envelope sealing for KMS providers. A fresh data key
#: (DEK) is wrapped by the KMS; the object is ``_codec`` wrapped and sealed under
#: the DEK with ``purpose``, ``tenant``, ``context``, codec, size and the wrapped
#: DEK as associated data. Every component is length-prefixed, so no separator
#: inside a value can shift a boundary. Earlier formats keep their exact bytes.
_DEK_LEN = struct.Struct(">H")
_MAX_WRAPPED_DEK = 1024


def aad5(purpose: str, tenant: str, context: str, codec: int, size: int, wrapped: bytes) -> bytes:
    parts = (
        purpose.encode("utf-8"),
        tenant.encode("utf-8"),
        context.encode("utf-8"),
        bytes([codec]),
        size.to_bytes(8, "big"),
        wrapped,
    )
    return b"opentine.sealed.v5\0" + b"".join(len(p).to_bytes(4, "big") + p for p in parts)


def envelope_seal(
    wrap: Any, purpose: str, tenant: str, context: str, plaintext: bytes, codec: str | None
) -> bytes:
    """``TINEAES5`` under a new DEK that *wrap(tenant, dek)* encrypts with the KMS."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from opentine import _codec

    wrapped_body = _codec.wrap(plaintext, codec) if codec else None
    wrapped_body = wrapped_body or _codec.wrap(plaintext, "raw", force=True)
    assert wrapped_body is not None
    codec_byte = wrapped_body[len(_codec.MAGIC)]
    dek = os.urandom(32)
    wrapped = wrap(tenant, dek)
    if not isinstance(wrapped, bytes) or not 0 < len(wrapped) <= _MAX_WRAPPED_DEK:
        raise ValueError("KMS returned an invalid wrapped data key")
    nonce = os.urandom(12)
    associated = aad5(purpose, tenant, context, codec_byte, len(plaintext), wrapped)
    header = SEALED5 + _DEK_LEN.pack(len(wrapped)) + wrapped
    header += bytes([codec_byte]) + len(plaintext).to_bytes(8, "big")
    return header + nonce + AESGCM(dek).encrypt(nonce, wrapped_body, associated)


def envelope_unseal(
    unwrap: Any, purpose: str, tenant: str, context: str, ciphertext: bytes, *, limit: int
) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from opentine import _codec

    start = len(SEALED5) + _DEK_LEN.size
    if len(ciphertext) < start or not ciphertext.startswith(SEALED5):
        raise ValueError("invalid encrypted object header")
    (length,) = _DEK_LEN.unpack_from(ciphertext, len(SEALED5))
    end = start + length
    if not 0 < length <= _MAX_WRAPPED_DEK or len(ciphertext) < end + 9 + 12:
        raise ValueError("invalid encrypted object header")
    wrapped = ciphertext[start:end]
    codec_byte = ciphertext[end]
    size = int.from_bytes(ciphertext[end + 1 : end + 9], "big")
    if size > limit:
        raise ValueError("encrypted object declares more bytes than the reader allows")
    dek = unwrap(tenant, wrapped)
    if not isinstance(dek, bytes) or len(dek) != 32:
        raise ValueError("KMS returned an invalid data key")
    nonce, body = ciphertext[end + 9 : end + 21], ciphertext[end + 21 :]
    associated = aad5(purpose, tenant, context, codec_byte, size, wrapped)
    inner = AESGCM(dek).decrypt(nonce, body, associated)
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
