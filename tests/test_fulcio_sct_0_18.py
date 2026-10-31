"""0.18 trust hardening: embedded Certificate Transparency SCTs on keyless certs.

Fully offline. ``SctFulcio`` extends the 0.15 fake Fulcio with a fake CT log:
it issues each leaf in the RFC 6962 precertificate flow -- build the cert,
take ``tbs_precertificate_bytes`` (TBS minus the SCT extension), sign the
``digitally-signed`` struct with the CT log key, then re-issue the identical
cert with the SCT list embedded. ``cryptography`` cannot build SCT objects, so
the extension value (a TLS ``SignedCertificateTimestampList`` inside a DER
OCTET STRING) is assembled by hand here.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import struct
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from opentine import Run, RunStatus, StepKind, cli, rekor
from tests._sigstore_fakes import IDENTITY, ISSUER_URL, FakeFulcio, FakeLog, fake_jwt, transport

TOKEN = fake_jwt({"iss": ISSUER_URL, "sub": "repo:o/r", "email": IDENTITY, "aud": "sigstore"})
SCT_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")


def _pem(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _der_len(n: int) -> bytes:
    return bytes([n]) if n < 0x80 else b"\x82" + n.to_bytes(2, "big")


def _sct_ext(scts: list[bytes]) -> x509.UnrecognizedExtension:
    body = b"".join(len(s).to_bytes(2, "big") + s for s in scts)
    tls = len(body).to_bytes(2, "big") + body
    return x509.UnrecognizedExtension(SCT_OID, b"\x04" + _der_len(len(tls)) + tls)


class SctFulcio(FakeFulcio):
    def __init__(self) -> None:
        super().__init__()
        self.ct_key = ec.generate_private_key(ec.SECP256R1())
        self.mode = "valid"  # valid | none | tamper | other-cert | late

    def _sct(self, tbs: bytes, when: dt.datetime) -> bytes:
        der = self.ct_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        issuer_hash = hashlib.sha256(
            self.inter_key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).digest()
        millis = int(when.timestamp() * 1000)
        signed = (struct.pack(">BBQH", 0, 0, millis, 1) + issuer_hash
                  + len(tbs).to_bytes(3, "big") + tbs + b"\x00\x00")  # fmt: skip
        sig = self.ct_key.sign(signed, ec.ECDSA(hashes.SHA256()))
        if self.mode == "tamper":
            sig = sig[:-1] + bytes([sig[-1] ^ 1])
        return (b"\x00" + hashlib.sha256(der).digest() + struct.pack(">Q", millis)
                + b"\x00\x00" + b"\x04\x03" + len(sig).to_bytes(2, "big") + sig)  # fmt: skip

    def issue(self, public) -> x509.Certificate:
        leaf = super().issue(public)
        if self.mode == "none":
            return leaf
        start, end = leaf.not_valid_before_utc, leaf.not_valid_after_utc
        extra = [e.value for e in leaf.extensions if not isinstance(e.value, x509.BasicConstraints)]
        serial = leaf.serial_number

        def build(scts: list[bytes]) -> x509.Certificate:
            builder = (x509.CertificateBuilder().subject_name(leaf.subject)
                       .issuer_name(leaf.issuer).public_key(public).serial_number(serial)
                       .not_valid_before(start).not_valid_after(end)
                       .add_extension(x509.BasicConstraints(False, None), True))  # fmt: skip
            for ext in [*extra, _sct_ext(scts)]:
                builder = builder.add_extension(ext, critical=False)
            cert = builder.sign(self.inter_key, hashes.SHA256())
            return x509.load_der_x509_certificate(cert.public_bytes(serialization.Encoding.DER))

        placeholder = self._sct(b"", start)
        tbs = build([placeholder]).tbs_precertificate_bytes
        if self.mode == "other-cert":
            serial += 1
            tbs, serial = build([placeholder]).tbs_precertificate_bytes, serial - 1
        when = end + dt.timedelta(hours=1) if self.mode == "late" else start
        return build([self._sct(tbs, when)])


@pytest.fixture
def ws(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    for name in ("SIGSTORE_ID_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="sct_src", model_info="mock-model", user_prompt="hello")
    run.add_step(StepKind.model, {"prompt": "hello"}, outputs={"text": "hi"}, model_info="m")
    run.status = RunStatus.completed
    run.save(tmp_path / "run.tine")
    log, fulcio = FakeLog(), SctFulcio()
    (tmp_path / "rekor.pub").write_bytes(log.public_pem())
    (tmp_path / "fulcio.pem").write_bytes(fulcio.roots_pem())
    (tmp_path / "ct.pub").write_bytes(_pem(fulcio.ct_key.public_key()))
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    (tmp_path / "other-ct.pub").write_bytes(_pem(other))
    monkeypatch.setattr(rekor, "TRANSPORT", transport(log, fulcio))
    return tmp_path, fulcio


def _cli(*argv: str) -> int:
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _export(fulcio: SctFulcio, mode: str = "valid") -> None:
    fulcio.mode = mode
    assert _cli("export", "run.tine", "--format", "intoto", "--keyless", "--rekor",
                "https://rekor.test", "--fulcio-url", "https://fulcio.test",
                "--identity-token", TOKEN, "--output", "a.sigstore.json") == 0  # fmt: skip


def _verify(capsys, *extra: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = _cli("verify", "run.tine", "--attestation", "a.sigstore.json", "--json",
                "--rekor-key", "rekor.pub", "--fulcio-root", "fulcio.pem",
                "--cert-identity", IDENTITY, "--cert-oidc-issuer", ISSUER_URL, *extra)  # fmt: skip
    return code, json.loads(capsys.readouterr().out)


def test_valid_sct_accepted(ws, capsys) -> None:
    _, fulcio = ws
    _export(fulcio)
    code, payload = _verify(capsys, "--ct-key", "ct.pub", "--require-sct")
    assert code == 0 and payload["signature"]["status"] == "verified-keyless"


def test_key_file_with_several_logs_and_repeated_flag(ws, capsys) -> None:
    root, fulcio = ws
    _export(fulcio)
    (root / "logs.pem").write_bytes((root / "other-ct.pub").read_bytes() + b"\n"
                                    + (root / "ct.pub").read_bytes())  # fmt: skip
    assert _verify(capsys, "--ct-key", "logs.pem")[0] == 0
    assert _verify(capsys, "--ct-key", "other-ct.pub", "--ct-key", "ct.pub")[0] == 0


@pytest.mark.parametrize(
    ("mode", "key", "reason"),
    [
        ("valid", "other-ct.pub", "no embedded SCT is from a log in --ct-key"),
        ("tamper", "ct.pub", "signature does not verify"),
        ("other-cert", "ct.pub", "signature does not verify"),
        ("none", "ct.pub", "no embedded SCT"),
        ("late", "ct.pub", "outside the certificate's validity"),
    ],
)
def test_bad_sct_fails_closed(ws, capsys, mode, key, reason) -> None:
    _, fulcio = ws
    _export(fulcio, mode)
    code, payload = _verify(capsys, "--ct-key", key)
    assert code == 1 and payload["ok"] is False
    assert reason in payload["signature"]["reason"]


def test_require_sct_without_ct_key_is_usage_error(ws, capsys) -> None:
    _, fulcio = ws
    _export(fulcio)
    capsys.readouterr()
    assert _cli("verify", "run.tine", "--attestation", "a.sigstore.json", "--require-sct") == 1
    assert "--require-sct needs --ct-key" in capsys.readouterr().out


@pytest.mark.parametrize("mode", ["valid", "none", "tamper"])
def test_no_flags_is_unchanged(ws, capsys, mode) -> None:
    _, fulcio = ws
    _export(fulcio, mode)
    code, payload = _verify(capsys)
    assert code == 0 and payload["signature"]["status"] == "verified-keyless"


def test_trust_policy_carries_ct_key(ws, capsys) -> None:
    root, fulcio = ws
    _export(fulcio, "tamper")
    assert _cli("trust", "policy", "set", "prod", "--rekor-key", "rekor.pub",
                "--fulcio-root", "fulcio.pem", "--cert-identity", IDENTITY,
                "--cert-oidc-issuer", ISSUER_URL, "--ct-key", "ct.pub",
                "--require-sct") == 0  # fmt: skip
    policy = json.loads((root / "cfg/opentine/trust-policies.json").read_text())
    assert policy["policies"]["prod"]["ct_key"] == [str(root / "ct.pub")]
    capsys.readouterr()
    assert _cli("verify", "run.tine", "--attestation", "a.sigstore.json", "--policy", "prod",
                "--json") == 1  # fmt: skip
    assert "SCT" in json.loads(capsys.readouterr().out)["signature"]["reason"]
    capsys.readouterr()
    pin = "sha256:" + "0" * 64
    assert _cli("trust", "policy", "set", "bad", "--pin", pin, "--ct-key", "ct.pub") == 1
    assert "keyless policy" in capsys.readouterr().out
