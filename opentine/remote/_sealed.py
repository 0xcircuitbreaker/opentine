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
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

SEALED = b"TINEAES3"
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
