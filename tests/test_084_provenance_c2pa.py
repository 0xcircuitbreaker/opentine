"""0.84: C2PA manifests via the optional ``c2pa`` extra (skipped when it is absent).

The manifest is written after the opentine pointer and validated by the
open-source C2PA library; the canonical digest ignores it; stripping it, or a
manifest naming another run, is detected. Without the extra a manifest reads as
``unchecked`` and never as valid.
"""

from __future__ import annotations

import datetime

import pytest

from opentine import _artifact_c2pa as c2pa_mod
from opentine import _artifact_trailer as trailer
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.provenance_fixture import _room, chunk, codes, embed, jpeg, png, verify  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _chain(tmp_path) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    def name(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, "test")])  # fmt: skip

    def cert(cn, key, issuer, ikey, ca):
        start = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
        usage = x509.KeyUsage(not ca, False, False, False, False, ca, ca, False, False)
        b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(issuer))
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(start).not_valid_after(start + datetime.timedelta(days=3650))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
             .add_extension(usage, True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                 ikey.public_key()), False))  # fmt: skip
        if not ca:
            b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
                                False)  # fmt: skip
        return b.sign(ikey, hashes.SHA256())

    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    pem = serialization.Encoding.PEM
    chain = (cert("leaf", leaf_key, "ca", ca_key, False).public_bytes(pem)
             + cert("ca", ca_key, "ca", ca_key, True).public_bytes(pem))  # fmt: skip
    private = leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())  # fmt: skip
    (tmp_path / "chain.pem").write_bytes(chain)
    (tmp_path / "leaf.pem").write_bytes(private)
    return (tmp_path / "chain.pem").as_posix(), (tmp_path / "leaf.pem").as_posix()


def test_without_the_extra_a_manifest_is_unchecked_never_valid(monkeypatch):
    monkeypatch.setattr(c2pa_mod, "library", lambda: None)
    data = png()
    fake = data[:33] + chunk(b"caBX", b"jumbf") + data[33:]
    assert c2pa_mod.check(fake)["state"] == "unchecked"
    assert trailer.digest(fake) == trailer.digest(data)
    with pytest.raises(RuntimeError):
        c2pa_mod.sign(data, run="r", artifact_digest="d", title="t", cert_chain=b"",
                      private_key=b"")  # fmt: skip


@pytest.mark.parametrize("name, make", [("a.png", png), ("a.jpg", jpeg)])
def test_a_c2pa_manifest_validates_and_names_the_run(capsys, room, name, make):
    pytest.importorskip("c2pa")
    cert, key = _chain(room["tmp"])
    path = room["tmp"] / name
    path.write_bytes(make())
    code, body = embed(capsys, room, path, "--c2pa-cert", cert, "--c2pa-key", key)
    assert code == 0 and body["c2pa"] is True and body["digest"] == trailer.digest(make())
    report = c2pa_mod.check(path.read_bytes())
    assert report["state"] == "valid" and report["run"] == room["run"]
    code, body = verify(capsys, room, path)
    assert (code, body["c2pa"], body["findings"]) == (0, "valid", [])
    path.write_bytes(trailer.embed(trailer.split(path.read_bytes())[0], room["run"])[0])
    code, body = verify(capsys, room, path)
    assert code == 1 and codes(body) == ["artifact.c2pa-stripped"]
