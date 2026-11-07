"""0.31.0: RFC 3161 timestamp tokens, attached beside a run and verified offline.

A throwaway CA and TSA are minted here with ``cryptography`` and every token is
assembled byte by byte below, so nothing depends on a live TSA or the network.
"""

from __future__ import annotations

import hashlib
import json
import socket
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from opentine import Run, RunStatus, StepKind, cli  # noqa: E402
from opentine._offline_guard import NetworkRefused, no_network  # noqa: E402
from opentine._timestamp_sidecar import bound_string, sidecar_path  # noqa: E402
from opentine._tsp_verify import verify_token  # noqa: E402

NOW = datetime.now(UTC).replace(microsecond=0)
SHA256 = "2.16.840.1.101.3.4.2.1"
POLICY = "1.3.6.1.4.1.99999.1"

# --------------------------------------------------------------------------- #
# byte-exact DER helpers
# --------------------------------------------------------------------------- #


def tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def der_set(*parts: bytes) -> bytes:
    return tlv(0x31, b"".join(sorted(parts)))


def integer(value: int) -> bytes:
    return tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big", signed=True))


def oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    body = bytearray()
    for arc in [40 * arcs[0] + arcs[1], *arcs[2:]]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, bytes(body))


def octets(data: bytes) -> bytes:
    return tlv(0x04, data)


def gentime(when: datetime) -> bytes:
    return tlv(0x18, when.strftime("%Y%m%d%H%M%SZ").encode())


# --------------------------------------------------------------------------- #
# a throwaway PKI and token builder
# --------------------------------------------------------------------------- #


def _cert(subject, issuer, key, signer, *, ca, eku=True, start=None, end=None):
    name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])  # noqa: E731
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start or NOW - timedelta(days=1))
        .not_valid_after(end or NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if eku and not ca:
        usage = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING])
        builder = builder.add_extension(usage, critical=True)
    return builder.sign(signer, hashes.SHA256())


def pki(**tsa_options):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert("Test Root", "Test Root", ca_key, ca_key, ca=True)
    tsa_key = ec.generate_private_key(ec.SECP256R1())
    tsa = _cert("Test TSA", "Test Root", tsa_key, ca_key, ca=False, **tsa_options)
    return ca, tsa, tsa_key


def token(
    bound: bytes, tsa, tsa_key, *, when=None, tamper=False, ess="v2", policy=POLICY, extra=b""
) -> bytes:
    """*ess*: ``v2`` (ESSCertIDv2, RFC 5816), ``v1``, ``none`` or ``wrong``; *extra*
    is appended to TSTInfo (accuracy, nonce, extensions)."""
    imprint = hashlib.sha256(bound).digest()
    tst = seq(
        integer(1),
        oid(policy),
        seq(seq(oid(SHA256), b"\x05\x00"), octets(imprint)),
        integer(42),
        gentime(when or NOW),
        extra,
    )
    attrs = [
        seq(oid("1.2.840.113549.1.9.3"), der_set(oid("1.2.840.113549.1.9.16.1.4"))),
        seq(oid("1.2.840.113549.1.9.4"), der_set(octets(hashlib.sha256(tst).digest()))),
    ]
    tsa_der = tsa.public_bytes(serialization.Encoding.DER)
    if ess == "v1":
        # RFC 2634 ESSCertID (v1) fixes the certHash to SHA-1. It only names
        # which certificate signed (an identifier the verifier compares, not a
        # security hash); v2 (the default) uses SHA-256.
        cert_id = seq(octets(hashlib.new("sha1", tsa_der, usedforsecurity=False).digest()))
        attrs.append(seq(oid("1.2.840.113549.1.9.16.2.12"), der_set(seq(seq(cert_id)))))
    elif ess in ("v2", "wrong"):
        digest = hashlib.sha256(tsa_der if ess == "v2" else b"other").digest()
        cert_id = seq(octets(digest))
        attrs.append(seq(oid("1.2.840.113549.1.9.16.2.47"), der_set(seq(seq(cert_id)))))
    signed_attrs = der_set(*attrs)
    signature = tsa_key.sign(signed_attrs, ec.ECDSA(hashes.SHA256()))
    if tamper:
        signature = signature[:-1] + bytes([signature[-1] ^ 1])
    issuer = tsa.issuer.public_bytes()
    signer = seq(
        integer(1),
        seq(issuer, integer(tsa.serial_number)),
        seq(oid(SHA256)),
        b"\xa0" + signed_attrs[1:],
        seq(oid("1.2.840.10045.4.3.2")),
        octets(signature),
    )
    cert_der = tsa.public_bytes(serialization.Encoding.DER)
    signed_data = seq(
        integer(3),
        der_set(seq(oid(SHA256))),
        seq(oid("1.2.840.113549.1.9.16.1.4"), tlv(0xA0, octets(tst))),
        tlv(0xA0, cert_der),
        der_set(signer),
    )
    content_info = seq(oid("1.2.840.113549.1.7.2"), tlv(0xA0, signed_data))
    return seq(seq(integer(0)), content_info)  # TimeStampResp, status granted


# --------------------------------------------------------------------------- #
# token-level checks
# --------------------------------------------------------------------------- #

BOUND = b"sha256:" + b"ab" * 32


def test_a_valid_token_verifies_and_reports_its_fields():
    ca, tsa, key = pki()
    verdict = verify_token(token(BOUND, tsa, key), BOUND, [ca])
    assert verdict.ok, verdict.detail
    assert verdict.reason == "timestamp.verified"
    assert verdict.info["policy"] == POLICY and verdict.info["hash_algorithm"] == "sha256"
    assert verdict.info["tsa"] == "CN=Test TSA"
    assert verdict.info["gen_time"].startswith(NOW.strftime("%Y-%m-%dT%H:%M:%S"))


@pytest.mark.parametrize(
    ("make", "reason"),
    [
        (lambda ca, tsa, k: (token(b"other", tsa, k), [ca]), "timestamp.imprint-mismatch"),
        (lambda ca, tsa, k: (token(BOUND, tsa, k, tamper=True), [ca]), "timestamp.bad-signature"),
        (lambda ca, tsa, k: (token(BOUND, tsa, k), [pki()[0]]), "timestamp.untrusted-root"),
        (
            lambda ca, tsa, k: (token(BOUND, tsa, k, when=NOW + timedelta(days=9)), [ca]),
            "timestamp.outside-validity",
        ),
    ],
    ids=["wrong-imprint", "tampered-signature", "untrusted-root", "gentime-outside-validity"],
)
def test_each_fault_fails_with_its_own_reason(make, reason):
    ca, tsa, key = pki()
    data, roots = make(ca, tsa, key)
    verdict = verify_token(data, BOUND, roots)
    assert not verdict.ok and verdict.reason == reason, verdict.detail


def test_a_tsa_certificate_without_the_timestamping_eku_fails():
    ca, tsa, key = pki(eku=False)
    verdict = verify_token(token(BOUND, tsa, key), BOUND, [ca])
    assert (verdict.ok, verdict.reason) == (False, "timestamp.missing-eku")


def test_no_root_is_unavailable_not_a_pass():
    _, tsa, key = pki()
    verdict = verify_token(token(BOUND, tsa, key), BOUND, [])
    assert not verdict.ok and verdict.no_roots and verdict.reason == "timestamp.no-roots"


@pytest.mark.parametrize(
    "garbage",
    [
        b"",
        b"\x00",
        b"\x30\x80\x00\x00",
        b"\x30\x05\x02\x01",
        b"not der at all",
        seq(integer(1)),
        seq(seq(integer(2))),
        seq(oid("1.2.3"), tlv(0xA0, seq())),
        bytes(range(256)),
    ],
)
def test_garbage_der_is_a_clean_failure(garbage):
    verdict = verify_token(garbage, BOUND, [])
    assert (verdict.ok, verdict.reason) == (False, "timestamp.malformed")


def test_every_truncation_of_a_valid_token_is_a_clean_failure():
    ca, tsa, key = pki()
    data = token(BOUND, tsa, key)
    for cut in range(0, len(data), 7):
        assert not verify_token(data[:cut], BOUND, [ca]).ok


# --------------------------------------------------------------------------- #
# attach + verify --offline end to end
# --------------------------------------------------------------------------- #


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="ts_run", model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    run.save(tmp_path / "run.tine")
    return tmp_path


def _tine(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    try:
        cli.main()
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _bound(path: Path) -> bytes:
    return bound_string(Run.verify_integrity(path)).encode()


def _report(monkeypatch, room: Path, *extra: str) -> tuple[int, dict]:
    code = _tine(monkeypatch, "verify", "run.tine", "--offline", "--report", "r.json", *extra)
    return code, json.loads((room / "r.json").read_text(encoding="utf-8"))


def test_attach_then_verify_offline_reports_the_timestamp(room, monkeypatch, capsys):
    ca, tsa, key = pki()
    assert _tine(monkeypatch, "timestamp", "data", "run.tine") == 0
    assert capsys.readouterr().out.encode() == _bound(room / "run.tine")
    (room / "t.tsr").write_bytes(token(_bound(room / "run.tine"), tsa, key))
    (room / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    assert _tine(monkeypatch, "timestamp", "attach", "run.tine", "t.tsr") == 0
    assert sidecar_path(room / "run.tine").is_file()

    code, report = _report(monkeypatch, room, "--tsa-roots", "ca.pem")
    stamp = next(c for c in report["checks"] if c["name"] == "timestamp")
    assert (code, stamp["outcome"], stamp["reason"]) == (0, "pass", "timestamp.verified")
    assert stamp["required"] is False and "ca.pem" in stamp["trust_basis"]
    (entry,) = report["timestamps"]
    assert entry["tsa"] == "CN=Test TSA" and entry["policy"] == POLICY
    assert entry["hash_algorithm"] == "sha256" and entry["gen_time"]

    code, report = _report(monkeypatch, room)  # no root: unavailable, not a pass
    stamp = next(c for c in report["checks"] if c["name"] == "timestamp")
    assert (code, stamp["outcome"]) == (0, "unavailable-offline")


def test_attach_refuses_a_token_for_other_bytes(room, monkeypatch):
    _, tsa, key = pki()
    (room / "t.tsr").write_bytes(token(b"something else", tsa, key))
    assert _tine(monkeypatch, "timestamp", "attach", "run.tine", "t.tsr") == 1
    (room / "g.tsr").write_bytes(b"garbage")
    assert _tine(monkeypatch, "timestamp", "attach", "run.tine", "g.tsr") == 1
    assert not sidecar_path(room / "run.tine").exists()


def test_an_untrusted_token_fails_the_offline_verdict(room, monkeypatch):
    _, tsa, key = pki()
    other_ca = pki()[0]
    (room / "t.tsr").write_bytes(token(_bound(room / "run.tine"), tsa, key))
    (room / "other.pem").write_bytes(other_ca.public_bytes(serialization.Encoding.PEM))
    assert _tine(monkeypatch, "timestamp", "attach", "run.tine", "t.tsr") == 0
    code, report = _report(monkeypatch, room, "--tsa-roots", "other.pem")
    assert code == 1 and report["verdict"] == "fail"
    stamp = next(c for c in report["checks"] if c["name"] == "timestamp")
    assert stamp["reason"] == "timestamp.untrusted-root"


def test_tsa_roots_needs_offline(room, monkeypatch):
    assert _tine(monkeypatch, "verify", "run.tine", "--tsa-roots", "ca.pem") == 1


def test_no_token_and_no_roots_leaves_the_report_unchanged(room, monkeypatch):
    _, report = _report(monkeypatch, room)
    assert "timestamps" not in report
    assert all(c["name"] != "timestamp" for c in report["checks"])


def test_verification_runs_under_the_network_guard(room, monkeypatch):
    ca, tsa, key = pki()
    (room / "t.tsr").write_bytes(token(_bound(room / "run.tine"), tsa, key))
    (room / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    assert _tine(monkeypatch, "timestamp", "attach", "run.tine", "t.tsr") == 0
    with no_network(), pytest.raises(NetworkRefused):
        socket.create_connection(("192.0.2.1", 80))
    with no_network():
        assert verify_token(token(BOUND, tsa, key), BOUND, [ca]).ok
    from opentine import _tsp_verify

    def dial(*_args, **_kwargs):
        socket.create_connection(("192.0.2.1", 80))

    monkeypatch.setattr(_tsp_verify, "verify_token", dial)
    code, report = _report(monkeypatch, room, "--tsa-roots", "ca.pem")
    assert code == 1
    assert any(c["reason"] == "offline.network-refused" for c in report["checks"])
