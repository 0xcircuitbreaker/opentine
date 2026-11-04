"""KMS key-provider adapter (``TINEAES5`` envelope since 0.35)."""

from __future__ import annotations

from collections.abc import Callable

from opentine.remote._sealed import SEALED5, check_legacy
from opentine.remote._sealed_envelope import envelope_seal, envelope_unseal


class KMSKeyProvider:
    """Adapter for KMS encrypt/decrypt and audit-key derivation callables.

    Since 0.35 it writes ``TINEAES5``: the KMS wraps a per-object data key, and the
    object is sealed under that key bound to its slot (``_sealed.envelope_seal``).
    Ciphertexts the callables wrote directly (``TINEAES2`` from older servers) still
    open unless legacy forms are refused."""

    def __init__(
        self,
        encrypt: Callable[[str, bytes], bytes],
        decrypt: Callable[[str, bytes], bytes],
        derive_audit_key: Callable[[], bytes] | None = None,
        *,
        refuse_legacy: bool = False,
    ):
        self._encrypt = encrypt
        self._decrypt = decrypt
        self._derive_audit_key = derive_audit_key
        self.refuse_legacy = refuse_legacy

    def seal(self, purpose: str, tenant: str, context: str, plaintext: bytes) -> bytes:
        return envelope_seal(self._encrypt, purpose, tenant, context, plaintext, None)

    def seal_compressed(
        self, purpose: str, tenant: str, context: str, plaintext: bytes, codec: str
    ) -> bytes:
        return envelope_seal(self._encrypt, purpose, tenant, context, plaintext, codec)

    def unseal(self, purpose: str, tenant: str, context: str, ciphertext: bytes) -> bytes:
        if ciphertext.startswith(SEALED5):
            from opentine.remote._object_file import MAX_ENCRYPTED_OBJECT_BYTES

            return envelope_unseal(
                self._decrypt,
                purpose,
                tenant,
                context,
                ciphertext,
                limit=MAX_ENCRYPTED_OBJECT_BYTES,
            )
        check_legacy(ciphertext, self.refuse_legacy)
        return self._decrypt(tenant, ciphertext)

    def encrypt(self, tenant: str, plaintext: bytes) -> bytes:
        return self._encrypt(tenant, plaintext)

    def decrypt(self, tenant: str, ciphertext: bytes) -> bytes:
        return self._decrypt(tenant, ciphertext)

    def derive_audit_key(self) -> bytes:
        if self._derive_audit_key is None:
            raise RuntimeError("KMS audit-key derivation is not configured")
        key = self._derive_audit_key()
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValueError("derived audit HMAC key must contain at least 16 bytes")
        return key
