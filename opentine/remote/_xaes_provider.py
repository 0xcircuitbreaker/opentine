"""``XAESKeyProvider``: a local provider that writes ``TINEAES6`` (0.41, X28).

It reads every earlier form through a ``LocalKeyProvider`` over the same master,
so turning it on needs no migration; ``tine serve reseal --to aes6`` rewrites
older objects. ``previous`` holds retired ``(key_id, epoch) -> master`` entries
so objects sealed before a rotation keep opening.
"""

from __future__ import annotations

import os

from opentine.remote._sealed6 import SEALED6, seal6, unseal6

KEY_ID_ENV, EPOCH_ENV, PAD_ENV = "TINE_KMS_KEY_ID", "TINE_KMS_KEY_EPOCH", "TINE_REMOTE_SEAL_PAD"


class XAESKeyProvider:
    """32-byte master, key id and epoch; XAES-256-GCM; optional Padme padding."""

    def __init__(
        self,
        key: bytes,
        key_id: str,
        epoch: int = 0,
        *,
        pad: bool = False,
        previous: dict[tuple[str, int], bytes] | None = None,
        refuse_legacy: bool = False,
    ):
        from opentine.remote.security import LocalKeyProvider

        if len(key) != 32:
            raise ValueError("TINEAES6 needs a 32-byte master key")
        self.key, self.key_id, self.epoch, self.pad = key, key_id, int(epoch), pad
        self.keyring = {**(previous or {}), (key_id, self.epoch): key}
        self.legacy = LocalKeyProvider(key, refuse_legacy=refuse_legacy)
        seal6(key, key_id, self.epoch, "probe", "probe", "", b"", None)  # validate id/epoch

    @classmethod
    def from_env(cls, key: bytes) -> XAESKeyProvider:
        try:
            epoch = int(os.environ.get(EPOCH_ENV, "0") or "0")
        except ValueError as exc:
            raise ValueError(f"{EPOCH_ENV} must be an integer") from exc
        pad = os.environ.get(PAD_ENV, "").strip().lower() in ("1", "true", "yes", "on")
        return cls(key, os.environ[KEY_ID_ENV], epoch, pad=pad)

    def seal(self, purpose: str, tenant: str, context: str, plaintext: bytes) -> bytes:
        return self._seal(purpose, tenant, context, plaintext, None)

    def seal_compressed(
        self, purpose: str, tenant: str, context: str, plaintext: bytes, codec: str
    ) -> bytes:
        return self._seal(purpose, tenant, context, plaintext, codec)

    def _seal(self, purpose, tenant, context, plaintext, codec) -> bytes:  # noqa: ANN001
        from opentine import _fips

        _fips.require("xaes-256-gcm")
        return seal6(
            self.key, self.key_id, self.epoch, purpose, tenant, context, plaintext, codec,
            pad=self.pad,
        )  # fmt: skip

    def unseal(self, purpose: str, tenant: str, context: str, ciphertext: bytes) -> bytes:
        from opentine.remote._object_file import MAX_ENCRYPTED_OBJECT_BYTES

        if ciphertext.startswith(SEALED6):
            limit = MAX_ENCRYPTED_OBJECT_BYTES
            return unseal6(self.keyring, purpose, tenant, context, ciphertext, limit=limit)
        return self.legacy.unseal(purpose, tenant, context, ciphertext)

    def encrypt(self, tenant: str, plaintext: bytes) -> bytes:
        return self.legacy.encrypt(tenant, plaintext)

    def decrypt(self, tenant: str, ciphertext: bytes) -> bytes:
        return self.legacy.decrypt(tenant, ciphertext)

    def derive_audit_key(self) -> bytes:
        return self.legacy.derive_audit_key()
