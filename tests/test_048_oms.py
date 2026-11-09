"""0.48: OMS model-signature checks as an assurance factor (SPEC 4.26).

The 75-oms family agrees in Python and the pyz (the TS verifier runs it in
``ts/verifier``'s own suite); the pure-Python P-256 verifier agrees with
OpenSSL; ``tine verify --model-signature`` records the factor in the run's
``assurance`` object, and a model that changed since signing fails the run.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest

from opentine import _oms, _schemas, cli
from opentine._pyz import _oms as pyz
from opentine._pyz import _p256
from opentine._signed_record import RecordError
from tests.conformance import tagged

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FAMILY = ROOT / "docs" / "conformance" / "vectors" / "75-oms.json"


@pytest.mark.parametrize("verifier", ["python", "pyz"])
def test_the_73_family_agrees_in_python_and_the_pyz(verifier):
    cases = json.loads(FAMILY.read_text("utf-8"))["cases"]
    assert len(cases) == 21
    for case in cases:
        value = tagged.decode(case["input"]["value"])
        key = value["public_key"]
        try:
            if verifier == "python":
                pinned = bytes.fromhex(key) if key else None
                got = _oms.check(value["bundle"], value["files"], pinned)
            else:
                got = pyz.oms_verify(value["bundle"], value["files"], key)
        except (RecordError, pyz.Refused) as exc:
            assert case["expect"] == "reject", case["id"]
            assert exc.code == case["reason"], case["id"]
            continue
        assert case["expect"] == "accept", case["id"]
        assert got["state"] == "verified" and got["label"] == _oms.LABEL


def test_p256_agrees_with_openssl_both_ways():
    for index in range(8):
        private = ec.generate_private_key(ec.SECP256R1())
        pem = private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        point = _p256.public_key(pem)
        message = b"message %d" % index
        signature = private.sign(message, ec.ECDSA(hashes.SHA256()))
        assert _p256.verify(point, message, signature)
        assert not _p256.verify(point, message + b"!", signature)
        assert not _p256.verify(point, message, signature[:-1])
    assert not _p256.verify(b"\x04" + b"\x00" * 64, b"m", b"0\x06\x02\x01\x01\x02\x01\x01")


# --- tine verify --model-signature -------------------------------------------- #


def _sign_model(model: Path, private: ec.EllipticCurvePrivateKey, bundle: Path) -> None:
    """Sign like model_signing's ``key`` method: files serialization, DSSE, P-256."""
    files = _oms.digest_dir(model)
    resources = [{"name": n, "algorithm": "sha256", "digest": d} for n, d in sorted(files.items())]
    root = hashlib.sha256(b"".join(bytes.fromhex(r["digest"]) for r in resources)).hexdigest()
    statement = {
        "_type": _oms.STATEMENT,
        "subject": [{"name": model.name, "digest": {"sha256": root}}],
        "predicateType": _oms.PREDICATE,
        "predicate": {
            "serialization": {"method": "files", "hash_type": "sha256", "ignore_paths": []},
            "resources": resources,
        },
    }
    payload = json.dumps(statement).encode()
    signature = private.sign(_oms.pae(_oms.PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256()))
    envelope = {
        "payload": base64.b64encode(payload).decode(),
        "payloadType": _oms.PAYLOAD_TYPE,
        "signatures": [{"sig": base64.b64encode(signature).decode(), "keyid": ""}],
    }
    media = "application/vnd.dev.sigstore.bundle.v0.3+json"
    document = {"mediaType": media,
                "verificationMaterial": {"publicKey": {"hint": "k"}},
                "dsseEnvelope": envelope}  # fmt: skip
    bundle.write_text(json.dumps(document), encoding="utf-8")


@pytest.fixture
def signed(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    model = tmp_path / "tiny-model"
    (model / "tokenizer").mkdir(parents=True)
    (model / "config.json").write_text("{}", encoding="utf-8")
    (model / "tokenizer" / "vocab.txt").write_text("a\n", encoding="utf-8")
    private = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "model.pub").write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    _sign_model(model, private, tmp_path / "model.sig")
    run = _run(tmp_path)
    return tmp_path, model, run


def _run(tmp_path: Path) -> str:
    source = tmp_path / "t.jsonl"
    base = {"sessionId": "s1", "timestamp": "2026-10-14T00:00:00Z"}
    lines = [{**base, "type": "user", "uuid": "u1", "message": {"role": "user", "content": "go"}}]
    source.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")
    argv = ["import", source.as_posix(), "--format", "claude-code-transcript", "--save", "r.tine"]
    assert _tine(*argv, "--force")[0] == 0
    return "r.tine"


def _tine(*argv: str) -> tuple[int, str]:
    old = sys.argv
    sys.argv = ["tine", *argv]
    try:
        cli.main()
    except SystemExit as exc:
        return int(exc.code or 0), ""
    finally:
        sys.argv = old
    return 0, ""


def _verify(capsys, run: str, *extra: str) -> tuple[int, dict]:
    capsys.readouterr()
    code, _ = _tine("verify", run, "--json", *extra)
    return code, json.loads(capsys.readouterr().out)


def test_a_signed_model_is_a_passing_factor(signed, capsys):
    room, model, run = signed
    flags = ("--model-signature", "model.sig", "--model", model.as_posix(), "--model-pubkey",
             "model.pub")  # fmt: skip
    code, report = _verify(capsys, run, *flags)
    factor = report["assurance"]["factors"][0]
    assert factor["factor"] == "oms-model-signature" and factor["ok"], factor
    assert factor["model"] == "tiny-model" and factor["files"] == 2 and factor["files_checked"]
    assert _schemas.validate(report["assurance"], "tine-assurance-1")[1] == []
    assert _schemas.validate(report, "tine-cli-verify-1")[1] == []
    assert code == 0, report
    code, offline = _verify(capsys, run, "--offline", *flags)
    checks = {c["name"]: c for c in offline["checks"]}
    assert checks["model-signature"]["outcome"] == "pass" and code == 0, offline


def test_a_changed_model_fails_the_run(signed, capsys):
    room, model, run = signed
    (model / "config.json").write_text('{"changed": true}', encoding="utf-8")
    flags = ("--model-signature", "model.sig", "--model", model.as_posix(), "--model-pubkey",
             "model.pub")  # fmt: skip
    code, report = _verify(capsys, run, *flags)
    factor = report["assurance"]["factors"][0]
    assert not factor["ok"] and factor["reason"] == "oms.digest-mismatch"
    assert code == 4, report
    code, offline = _verify(capsys, run, "--offline", *flags)
    checks = {c["name"]: c for c in offline["checks"]}
    assert checks["model-signature"]["reason"] == "oms.digest-mismatch" and code != 0


def test_no_key_and_no_flag(signed, capsys):
    room, model, run = signed
    code, report = _verify(capsys, run, "--model-signature", "model.sig")
    assert report["assurance"]["factors"][0]["reason"] == "oms.no-key" and code != 0
    code, report = _verify(capsys, run)
    assert "factors" not in report["assurance"]
