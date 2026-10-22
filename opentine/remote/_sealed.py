"""Purpose- and object-bound sealing for data at rest (``TINEAES3``).

``TINEAES1``/``TINEAES2`` bind a ciphertext to its tenant only, so an object file
and an upload frame -- or two objects, or frames of two uploads -- encrypted for
the same tenant were interchangeable under the key. Integrity still held (an
object's content hash is checked on read; a pack's checksum at install), but a
ciphertext could be moved between slots without the key noticing. ``TINEAES3``
authenticates ``purpose || tenant || context`` (the oid, or the upload id and
offset), so a ciphertext opens only in the slot it was written for.

A key provider opts in by implementing ``seal``/``unseal``; one that only has
``encrypt``/``decrypt`` (a KMS adapter written before 0.9.2) keeps working
unbound. Older ciphertexts always still open.

``TINEAES4`` (0.12) compresses before it seals: the plaintext is a ``_codec``
wrapper, and the codec byte and uncompressed length are in the clear header and
bound into the associated data, so a ciphertext cannot be relabelled with a
different codec or a larger size to make the reader inflate a bomb. A provider
opts in with ``seal_compressed``. Upload frames are never compressed (they hold
packs, already compressed). Ciphertext length now reflects how well an object
compresses; objects are per tenant and at rest, and an operator can store a
tenant uncompressed (``FilesystemObjectStore(uncompressed_tenants=...)``).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

SEALED = b"TINEAES3"
SEALED4 = b"TINEAES4"
_HEADER4 = len(SEALED4) + 1 + 8  # magic, codec byte, uncompressed length (u64 BE)
OBJECT = "object"
UPLOAD_FRAME = "upload-frame"


def aad(purpose: str, tenant: str, context: str) -> bytes:
    parts = (purpose, tenant, context)
    return b"opentine.sealed.v3\0" + b"\0".join(part.encode("utf-8") for part in parts)


def tenant_key(master: bytes, tenant: str) -> bytes:
    return hmac.new(master, b"opentine.tenant-key.v1\0" + tenant.encode(), hashlib.sha256).digest()


def seal_with(master: bytes, purpose: str, tenant: str, context: str, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    key = AESGCM(tenant_key(master, tenant))
    return SEALED + nonce + key.encrypt(nonce, plaintext, aad(purpose, tenant, context))


def unseal_with(master: bytes, purpose: str, tenant: str, context: str, ciphertext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce, body = ciphertext[8:20], ciphertext[20:]
    key = AESGCM(tenant_key(master, tenant))
    return key.decrypt(nonce, body, aad(purpose, tenant, context))


def seal(keys: Any, purpose: str, tenant: str, context: str, plaintext: bytes) -> bytes:
    sealer = getattr(keys, "seal", None)
    if callable(sealer):
        return sealer(purpose, tenant, context, plaintext)
    return keys.encrypt(tenant, plaintext)


def unseal(keys: Any, purpose: str, tenant: str, context: str, ciphertext: bytes) -> bytes:
    opener = getattr(keys, "unseal", None)
    if callable(opener):
        return opener(purpose, tenant, context, ciphertext)
    return keys.decrypt(tenant, ciphertext)


def aad4(purpose: str, tenant: str, context: str, codec: int, size: int) -> bytes:
    parts = (purpose, tenant, context, str(codec), str(size))
    return b"opentine.sealed.v4\0" + b"\0".join(part.encode("utf-8") for part in parts)


def seal_compressed_with(
    master: bytes, purpose: str, tenant: str, context: str, plaintext: bytes, codec: str
) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from opentine import _codec

    wrapped = _codec.wrap(plaintext, codec) or _codec.wrap(plaintext, "raw", force=True)
    assert wrapped is not None
    codec_byte = wrapped[len(_codec.MAGIC)]
    header = SEALED4 + bytes([codec_byte]) + len(plaintext).to_bytes(8, "big")
    nonce = os.urandom(12)
    key = AESGCM(tenant_key(master, tenant))
    associated = aad4(purpose, tenant, context, codec_byte, len(plaintext))
    return header + nonce + key.encrypt(nonce, wrapped, associated)


def unseal_compressed_with(
    master: bytes, purpose: str, tenant: str, context: str, ciphertext: bytes, *, limit: int
) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from opentine import _codec

    if len(ciphertext) < _HEADER4 + 12 or not ciphertext.startswith(SEALED4):
        raise ValueError("invalid encrypted object header")
    codec_byte = ciphertext[len(SEALED4)]
    size = int.from_bytes(ciphertext[len(SEALED4) + 1 : _HEADER4], "big")
    if size > limit:
        raise ValueError("encrypted object declares more bytes than the reader allows")
    nonce, body = ciphertext[_HEADER4 : _HEADER4 + 12], ciphertext[_HEADER4 + 12 :]
    key = AESGCM(tenant_key(master, tenant))
    wrapped = key.decrypt(nonce, body, aad4(purpose, tenant, context, codec_byte, size))
    if (
        not _codec.is_wrapped(wrapped)
        or wrapped[len(_codec.MAGIC)] != codec_byte
        or _codec.declared_size(wrapped) != size
    ):
        raise ValueError("encrypted object does not match its header")
    try:
        return _codec.unwrap(wrapped, limit=size)
    except _codec.CodecError as exc:
        raise ValueError("encrypted object body is corrupt") from exc


def seal_object(keys: Any, tenant: str, oid: str, plaintext: bytes, codec: str | None) -> bytes:
    """An object file: compressed then sealed when *codec* and the provider allow it."""
    sealer = getattr(keys, "seal_compressed", None)
    if codec and callable(sealer):
        return sealer(OBJECT, tenant, oid, plaintext, codec)
    return seal(keys, OBJECT, tenant, oid, plaintext)


#: Operator switch for at-rest compression: ``off`` keeps writing ``TINEAES3``
#: (needed before rolling a server back to 0.11, which cannot read ``TINEAES4``).
CODEC_ENV = "TINE_REMOTE_STORAGE_CODEC"


def storage_codec(configured: str | None = "default") -> str | None:
    """The codec new objects are stored with, or ``None`` for uncompressed (AES3)."""
    from opentine import _codec

    choice = os.environ.get(CODEC_ENV, "").strip().lower() or configured
    if choice in (None, "", "0", "off", "none", "raw", "false", "no"):
        return None
    if choice == "default":
        return _codec.default_codec()
    if choice not in ("zlib", "zstd"):
        raise ValueError(f"{CODEC_ENV} must be off, zlib or zstd")
    if not _codec.available(choice):
        raise ValueError(f"{choice} is not available on this server; install opentine[zstd]")
    return choice
