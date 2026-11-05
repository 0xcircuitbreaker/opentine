"""0.35: the KMS adapter seals slot-bound (TINEAES5); legacy seals can be refused."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from opentine.remote import _sealed, _sealed_envelope
from opentine.remote._admin_reseal import reseal
from opentine.remote.backend import FilesystemObjectStore
from opentine.remote.security import KMSKeyProvider, LocalKeyProvider
from opentine.repository import Repo

KEY = b"k" * 32
OID_A = "blob:sha256:" + "a" * 64
OID_B = "blob:sha256:" + "b" * 64


def _kms(**kwargs) -> KMSKeyProvider:
    """The adapter as a deployment wires it: a KMS that encrypts bytes per tenant."""
    local = LocalKeyProvider(KEY)
    return KMSKeyProvider(local.encrypt, local.decrypt, **kwargs)


def test_kms_ciphertext_moved_to_another_slot_does_not_open():
    keys = _kms()
    sealed = _sealed.seal_object(keys, "acme", OID_A, b"secret", "zlib")
    assert sealed.startswith(_sealed.SEALED5)
    assert _sealed.unseal(keys, _sealed.OBJECT, "acme", OID_A, sealed) == b"secret"
    for purpose, tenant, context in (
        (_sealed.OBJECT, "acme", OID_B),
        (_sealed.UPLOAD_FRAME, "acme", OID_A),
        (_sealed.OBJECT, "other", OID_A),
    ):
        with pytest.raises((InvalidTag, ValueError)):
            _sealed.unseal(keys, purpose, tenant, context, sealed)


def test_kms_header_cannot_be_relabelled():
    keys = _kms()
    sealed = bytearray(_sealed.seal_object(keys, "acme", OID_A, b"x" * 100, None))
    sealed[-30] ^= 1
    with pytest.raises((InvalidTag, ValueError)):
        _sealed.unseal(keys, _sealed.OBJECT, "acme", OID_A, bytes(sealed))


def test_aad5_is_length_prefixed():
    assert _sealed_envelope.aad5("o", "a\0b", "c", 0, 1, b"w") != _sealed_envelope.aad5(
        "o", "a", "b\0c", 0, 1, b"w"
    )


def test_old_kms_tineaes2_still_opens_and_can_be_refused(monkeypatch):
    legacy = LocalKeyProvider(KEY).encrypt("acme", b"old")
    assert _sealed.unseal(_kms(), _sealed.OBJECT, "acme", OID_A, legacy) == b"old"
    with pytest.raises(ValueError, match="legacy"):
        _sealed.unseal(_kms(refuse_legacy=True), _sealed.OBJECT, "acme", OID_A, legacy)
    with pytest.raises(ValueError, match="legacy"):
        LocalKeyProvider(KEY, refuse_legacy=True).unseal(_sealed.OBJECT, "acme", OID_A, legacy)
    monkeypatch.setenv(_sealed.REFUSE_LEGACY_ENV, "1")
    with pytest.raises(ValueError, match="legacy"):
        _sealed.unseal(_kms(), _sealed.OBJECT, "acme", OID_A, legacy)
    tineaes1 = b"TINEAES1" + b"\0" * 12 + AESGCM(KEY).encrypt(b"\0" * 12, b"v1", b"acme")
    with pytest.raises(ValueError, match="legacy"):
        LocalKeyProvider(KEY).unseal(_sealed.OBJECT, "acme", OID_A, tineaes1)


def test_reseal_from_aes2_rewrites_legacy_objects(tmp_path):
    keys = _kms()
    store = FilesystemObjectStore(tmp_path / "objects", keys)
    oid = Repo.init(tmp_path / "local").put("blob", b"payload" * 20, redact=False)
    data = Repo.open(tmp_path / "local").raw(oid)
    store.put("acme", oid, data)
    path = store._path("acme", oid)
    path.write_bytes(LocalKeyProvider(KEY).encrypt("acme", data))  # a pre-0.35 KMS write
    assert reseal(store, "acme", "aes4", source="aes2").rewritten == 1
    assert path.read_bytes().startswith(_sealed.SEALED5)
    assert reseal(store, "acme", "aes4", source="aes2").rewritten == 0
    strict = FilesystemObjectStore(tmp_path / "objects", _kms(refuse_legacy=True))
    assert strict.get("acme", oid) == data


def test_env_refusal_also_covers_providers_without_unseal(monkeypatch):
    class Plain:
        def decrypt(self, tenant, ciphertext):
            return b"opened"

    assert _sealed.unseal(Plain(), "object", "t", "oid", b"TINEAES2xx") == b"opened"
    monkeypatch.setenv(_sealed.REFUSE_LEGACY_ENV, "1")
    with pytest.raises(ValueError, match="legacy"):
        _sealed.unseal(Plain(), "object", "t", "oid", b"TINEAES2xx")
