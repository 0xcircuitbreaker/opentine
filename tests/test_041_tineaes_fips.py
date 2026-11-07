"""0.41: TINEAES6 (roadmap X28: key id, epoch, XAES-256-GCM, Padme) and --fips (X30)."""

from __future__ import annotations

import hashlib
import hmac

import pytest
from cryptography.exceptions import InvalidTag

from opentine import _fips
from opentine.remote import _sealed, _sealed6, _xaes
from opentine.remote._admin_reseal import reseal
from opentine.remote._xaes_provider import XAESKeyProvider
from opentine.remote.backend import FilesystemObjectStore
from opentine.remote.security import KMSKeyProvider, LocalKeyProvider
from opentine.repository import Repo

KEY = b"m" * 32
OID_A = "blob:sha256:" + "a" * 64
OID_B = "blob:sha256:" + "b" * 64
NONCE = b"ABCDEFGHIJKLMNOPQRSTUVWX"


# -- XAES-256-GCM: the C2SP test vectors ------------------------------------------


@pytest.mark.parametrize(
    ("key", "aad", "expected"),
    [
        (b"\x01" * 32, None, "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"),
        (
            b"\x03" * 32,
            b"c2sp.org/XAES-256-GCM",
            "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d",
        ),
    ],
)
def test_xaes_256_gcm_c2sp_vectors(key, aad, expected):
    assert _xaes.encrypt(key, NONCE, b"XAES-256-GCM", aad).hex() == expected
    assert _xaes.decrypt(key, NONCE, bytes.fromhex(expected), aad) == b"XAES-256-GCM"


def test_xaes_rejects_wrong_sizes_and_tampering():
    with pytest.raises(ValueError):
        _xaes.encrypt(b"k" * 16, NONCE, b"x", None)
    with pytest.raises(ValueError):
        _xaes.encrypt(KEY, NONCE[:12], b"x", None)
    sealed = bytearray(_xaes.encrypt(KEY, NONCE, b"hello", b"ad"))
    sealed[0] ^= 1
    with pytest.raises(InvalidTag):
        _xaes.decrypt(KEY, NONCE, bytes(sealed), b"ad")


def test_padme_matches_the_reference_sizes():
    assert [_xaes.padme(n) for n in (0, 1, 2, 3, 9, 100, 1000, 1025)] == [
        0, 1, 2, 3, 10, 104, 1024, 1088,
    ]  # fmt: skip
    for n in range(2, 5000):
        assert n <= _xaes.padme(n) <= n * 1.125 + 1


# -- TINEAES6 ---------------------------------------------------------------------


def _keys(**kwargs) -> XAESKeyProvider:
    return XAESKeyProvider(KEY, kwargs.pop("key_id", "k1"), kwargs.pop("epoch", 3), **kwargs)


@pytest.mark.parametrize("codec", [None, "zlib"])
@pytest.mark.parametrize("pad", [False, True])
def test_tineaes6_round_trips_and_records_key_id_and_epoch(codec, pad):
    keys = _keys(pad=pad)
    plain = b"payload " * 300
    sealed = _sealed.seal_object(keys, "acme", OID_A, plain, codec)
    assert sealed.startswith(_sealed.SEALED6)
    key_id, epoch, flags, _codec, size, _ = _sealed6.parse_header(sealed)
    assert (key_id, epoch, size, bool(flags & _sealed6.PADDED)) == ("k1", 3, len(plain), pad)
    assert _sealed.unseal(keys, _sealed.OBJECT, "acme", OID_A, sealed) == plain


def test_padding_is_optional_and_hides_the_exact_length():
    def lengths(keys):
        sizes = (1100, 1101, 1110)
        return {len(_sealed.seal_object(keys, "t", OID_A, b"x" * n, None)) for n in sizes}

    assert len(lengths(_keys())) == 3
    assert len(lengths(_keys(pad=True))) == 1


def test_tineaes6_is_bound_to_slot_key_id_and_epoch():
    keys = _keys()
    sealed = _sealed.seal_object(keys, "acme", OID_A, b"secret", None)
    for purpose, tenant, context in (
        (_sealed.OBJECT, "acme", OID_B),
        (_sealed.UPLOAD_FRAME, "acme", OID_A),
        (_sealed.OBJECT, "other", OID_A),
    ):
        with pytest.raises((InvalidTag, ValueError)):
            _sealed.unseal(keys, purpose, tenant, context, sealed)
    # Relabel the epoch (and keep a key under the forged label): the AAD catches it.
    key_id, epoch, *_, at = _sealed6.parse_header(sealed)
    epoch_at = len(_sealed6.SEALED6) + 1 + len(key_id)
    forged = bytearray(sealed)
    forged[epoch_at + 3] ^= 1
    keyring = {("k1", 3): KEY, ("k1", 2): KEY}
    with pytest.raises(InvalidTag):
        _sealed6.unseal6(keyring, _sealed.OBJECT, "acme", OID_A, bytes(forged), limit=1 << 20)
    # Flip the padded flag, or any ciphertext byte.
    for index in (epoch_at + 4, len(sealed) - 1, at + 30):
        tampered = bytearray(sealed)
        tampered[index] ^= 1
        with pytest.raises((InvalidTag, ValueError)):
            _sealed.unseal(keys, _sealed.OBJECT, "acme", OID_A, bytes(tampered))


def test_rotation_keeps_old_epochs_readable_and_unknown_keys_fail_clearly():
    old = _sealed.seal_object(_keys(epoch=1), "acme", OID_A, b"before", None)
    rotated = XAESKeyProvider(b"n" * 32, "k1", 2, previous={("k1", 1): KEY})
    assert _sealed.unseal(rotated, _sealed.OBJECT, "acme", OID_A, old) == b"before"
    with pytest.raises(ValueError, match="no master key"):
        _sealed.unseal(XAESKeyProvider(KEY, "k2"), _sealed.OBJECT, "acme", OID_A, old)


def test_tineaes6_needs_a_32_byte_master_and_a_valid_key_id():
    with pytest.raises(ValueError):
        XAESKeyProvider(b"k" * 16, "k1")
    for bad in ("", "x" * 65):
        with pytest.raises(ValueError):
            XAESKeyProvider(KEY, bad)


def test_older_formats_still_open():
    keys = _keys()
    local = LocalKeyProvider(KEY)
    for sealed in (
        local.encrypt("acme", b"old"),  # TINEAES2
        local.seal(_sealed.OBJECT, "acme", OID_A, b"old"),  # TINEAES3
        local.seal_compressed(_sealed.OBJECT, "acme", OID_A, b"old", "zlib"),  # TINEAES4
    ):
        assert _sealed.unseal(keys, _sealed.OBJECT, "acme", OID_A, sealed) == b"old"
    kms = KMSKeyProvider(local.encrypt, local.decrypt)  # TINEAES5 still opens via its provider
    aes5 = _sealed.seal_object(kms, "acme", OID_A, b"old", "zlib")
    assert _sealed.unseal(kms, _sealed.OBJECT, "acme", OID_A, aes5) == b"old"


def test_env_selects_tineaes6(monkeypatch):
    import base64

    monkeypatch.setenv("TINE_KMS_KEY", base64.b64encode(KEY).decode())
    assert isinstance(LocalKeyProvider.from_env(), LocalKeyProvider)
    monkeypatch.setenv("TINE_KMS_KEY_ID", "prod-2026")
    monkeypatch.setenv("TINE_KMS_KEY_EPOCH", "7")
    monkeypatch.setenv("TINE_REMOTE_SEAL_PAD", "1")
    keys = LocalKeyProvider.from_env()
    assert isinstance(keys, XAESKeyProvider)
    assert (keys.key_id, keys.epoch, keys.pad) == ("prod-2026", 7, True)


def test_reseal_to_aes6_rewrites_older_objects(tmp_path):
    local_store = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(KEY))
    oid = Repo.init(tmp_path / "local").put("blob", b"payload" * 20, redact=False)
    data = Repo.open(tmp_path / "local").raw(oid)
    local_store.put("acme", oid, data)
    with pytest.raises(ValueError, match="aes6"):
        reseal(local_store, "acme", "aes6")
    store = FilesystemObjectStore(tmp_path / "objects", _keys())
    assert reseal(store, "acme", "aes6", dry_run=True).rewritten == 1
    assert reseal(store, "acme", "aes6").rewritten == 1
    assert store._path("acme", oid).read_bytes().startswith(_sealed.SEALED6)
    assert reseal(store, "acme", "aes6").rewritten == 0
    assert store.get("acme", oid) == data
    reseal(store, "acme", "aes4")  # and an aes6 object can be resealed onward
    assert store.get("acme", oid) == data


# -- FIPS mode --------------------------------------------------------------------


def test_fips_refuses_non_approved_primitives(monkeypatch):
    monkeypatch.setenv(_fips.ENV, "1")
    for primitive in ("chacha20-poly1305", "xz-crc64", "md5"):
        with pytest.raises(_fips.FipsError, match="refused under --fips"):
            _fips.require(primitive)
    for primitive in ("hmac-sha256", "ed25519", "aes-256-gcm", "xaes-256-gcm"):
        _fips.require(primitive)
    from opentine import _codec_xz

    with pytest.raises(_fips.FipsError):
        _codec_xz.compress(b"x", None, ValueError)
    monkeypatch.delenv(_fips.ENV)
    _fips.require("chacha20-poly1305")  # outside FIPS mode nothing is refused


def test_fips_accepts_hmac_and_ed25519_signing(monkeypatch):
    from opentine._signing_verify import ALGORITHMS

    monkeypatch.setenv(_fips.ENV, "1")
    for algorithm in ALGORITHMS:
        _fips.require(algorithm)
    assert hmac.new(b"k" * 32, b"m", hashlib.sha256).digest()


def test_fips_flag_needs_the_provider(monkeypatch, capsys):
    from opentine import cli

    monkeypatch.setenv(_fips.ENV, "0")  # restored afterwards; --fips sets it to 1
    monkeypatch.setattr(_fips, "provider_active", lambda: False)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--fips", "ls"])
    assert exc.value.code == 6
    assert "FIPS provider" in capsys.readouterr().err


def test_fips_mode_is_recorded_in_verify_reports(monkeypatch):
    from opentine._verify_report import Report

    assert "crypto" not in Report("run.tine").as_json()
    monkeypatch.setenv(_fips.ENV, "1")
    monkeypatch.setattr(_fips, "provider_active", lambda: True)
    crypto = Report("run.tine").as_json()["crypto"]
    assert crypto["mode"] == "fips" and crypto["provider_fips"] is True
    assert crypto["openssl"].startswith("OpenSSL")


@pytest.mark.skipif(not _fips.provider_active(), reason="OpenSSL FIPS provider not active")
def test_real_fips_provider_runs_tineaes6_and_hmac(monkeypatch):
    """The ``fips`` CI job (UBI 9, OpenSSL 3 FIPS provider) is the real gate."""
    monkeypatch.setenv(_fips.ENV, "1")
    _fips.require_provider()
    keys = _keys(pad=True)
    sealed = _sealed.seal_object(keys, "acme", OID_A, b"fips", "zlib")
    assert _sealed.unseal(keys, _sealed.OBJECT, "acme", OID_A, sealed) == b"fips"
    assert hmac.new(b"k" * 32, b"m", hashlib.sha256).digest()
    from cryptography.exceptions import InternalError, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    # Ed25519 is FIPS 186-5, but a FIPS provider may not ship it, and
    # cryptography's ed25519_supported() probe does not ask the provider.
    try:
        private = Ed25519PrivateKey.generate()
    except (InternalError, UnsupportedAlgorithm):
        return
    private.public_key().verify(private.sign(b"m"), b"m")


def test_opentine_imports_where_hashlib_has_no_md5(monkeypatch):
    """A FIPS-only Python has no hashlib.md5; httpx needs it at import."""
    from opentine import _fips_shim

    monkeypatch.delattr(hashlib, "md5")
    assert _fips_shim.install() is True
    with pytest.raises(ValueError, match="FIPS"):
        hashlib.md5(b"x")
    assert _fips_shim.install() is False
