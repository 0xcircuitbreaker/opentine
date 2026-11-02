"""0.25.0 phases 1-2: ``tine verify RUN --offline`` and the tine-verify-report/1.

Everything runs in process under a temporary HOME/XDG, and the socket module is
monkeypatched so a test fails if anything dials.
"""

from __future__ import annotations

import json
import re
import socket
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._offline_guard import NetworkRefused, no_network
from opentine._verify_report import JSON_SCHEMA, SCHEMA, Check, Report
from opentine.signing import HAS_ED25519, generate_ed25519

needs_ed25519 = pytest.mark.skipif(not HAS_ED25519, reason="ed25519 needs the crypto extra")


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    monkeypatch.delenv("OPENTINE_OUTPUT", raising=False)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="offline_source", model_info="mock-model", user_prompt="test prompt")
    run.add_step(StepKind.think, {"text": "thinking"})
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    run.save(tmp_path / "source.tine")
    if HAS_ED25519:
        seed, public = generate_ed25519()
        (tmp_path / "ed.pub").write_text(public + "\n", encoding="utf-8")
        (tmp_path / "ed.hex").write_text(seed + "\n", encoding="utf-8")
        run.save(tmp_path / "ed.tine", sign_key=seed, sign_algorithm="ed25519")
    return tmp_path


@pytest.fixture
def dials(monkeypatch) -> list[str]:
    """Record (and refuse) every dial, so the guard is not the only thing proving it."""
    calls: list[str] = []

    def record(name):
        def fake(*_a, **_k):
            calls.append(name)
            raise OSError(f"test refused {name}")

        return fake

    monkeypatch.setattr(socket, "getaddrinfo", record("getaddrinfo"))
    monkeypatch.setattr(socket, "create_connection", record("create_connection"))
    monkeypatch.setattr(socket.socket, "connect", record("connect"))
    return calls


def _invoke(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


def _report(capsys, *argv: str) -> tuple[int, dict]:
    code, out = _invoke(capsys, "verify", *argv, "--offline", "--json")
    return code, json.loads(out)


def _check(doc: dict, name: str) -> dict:
    return next(c for c in doc["checks"] if c["name"] == name)


def _validate(doc: dict) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(doc, JSON_SCHEMA)


def test_unsigned_run_digest_passes_signature_unavailable(room, capsys, dials):
    code, doc = _report(capsys, "source.tine")
    assert code == 0 and doc["schema"] == SCHEMA and doc["verdict"] == "pass"
    digest, signature = _check(doc, "digest"), _check(doc, "signature")
    assert digest["outcome"] == "pass" and digest["reason"] == "digest.match"
    assert "internal consistency only" in digest["trust_basis"]
    assert signature["outcome"] == "unavailable-offline"
    assert signature["reason"] == "signature.unsigned"
    assert signature["trust_basis"].startswith("none")
    assert doc["authorship"] is None  # consistency is never authorship
    assert _check(doc, "attestation")["outcome"] == "not-applicable"
    assert dials == []
    _validate(doc)


def test_human_rendering_states_the_trust_basis(room, capsys, dials):
    code, out = _invoke(capsys, "verify", "source.tine", "--offline")
    flat = re.sub(r"\s+", " ", out)
    assert code == 0 and "VERIFIED (offline)" in flat
    assert "trust basis: internal consistency only" in flat
    assert "authorship: NOT established" in flat and "signature.unsigned" in flat


@needs_ed25519
def test_ed25519_signed_run_with_pubkey_passes(room, capsys, dials):
    code, doc = _report(capsys, "ed.tine", "--pubkey", "ed.pub")
    signature = _check(doc, "signature")
    assert code == 0 and signature["outcome"] == "pass"
    assert signature["reason"] == "signature.verified"
    assert re.match(r"supplied key sha256:[0-9a-f]{64} \(--pubkey\)", signature["trust_basis"])
    assert doc["authorship"] == signature["trust_basis"]
    _validate(doc)


@needs_ed25519
def test_signed_run_without_a_key_is_unavailable_and_tofu_is_not_authorship(room, capsys):
    code, doc = _report(capsys, "ed.tine")
    assert code == 0 and _check(doc, "signature")["reason"] == "signature.no-key"
    code, doc = _report(capsys, "ed.tine", "--trust-embedded-key")
    signature = _check(doc, "signature")
    assert code == 0 and signature["outcome"] == "pass"
    assert "trust-on-first-use" in signature["trust_basis"] and doc["authorship"] is None


def test_a_tampered_byte_fails_with_a_reason_code(room, capsys, dials):
    raw = (room / "source.tine").read_bytes()
    (room / "bad.tine").write_bytes(raw.replace(b"thinking", b"thinkinG", 1))
    code, doc = _report(capsys, "bad.tine")
    digest = _check(doc, "digest")
    assert code == 1 and doc["verdict"] == "fail" and not doc["ok"]
    assert digest["outcome"] == "fail" and digest["reason"] == "digest.mismatch"
    assert _check(doc, "signature")["outcome"] == "not-applicable"
    _validate(doc)


def test_unparseable_artifact_reuses_the_conformance_code(room, capsys):
    (room / "junk.tine").write_text("not json", encoding="utf-8")
    code, doc = _report(capsys, "junk.tine")
    assert code == 1 and _check(doc, "digest")["reason"] == "artifact.malformed-json"


def test_strict_fails_when_a_required_check_is_unavailable(room, capsys):
    code, doc = _report(capsys, "source.tine", "--strict")
    assert code == 1 and doc["verdict"] == "fail" and doc["unavailable_required"] == ["signature"]
    _validate(doc)


@needs_ed25519
def test_strict_passes_when_every_required_check_ran(room, capsys):
    code, doc = _report(capsys, "ed.tine", "--pubkey", "ed.pub", "--strict")
    assert code == 0 and doc["verdict"] == "pass" and doc["unavailable_required"] == []


def test_report_file_matches_stdout_and_validates(room, capsys):
    code, doc = _report(capsys, "source.tine", "--report", "out/report.json")
    written = json.loads((room / "out" / "report.json").read_text(encoding="utf-8"))
    assert code == 0 and written == doc
    _validate(written)


def test_report_model_verdict_rules():
    report = Report("x", checks=[Check("a", "pass", "a.ok", "", required=True)])
    report.add(Check("b", "unavailable-offline", "b.no-key", "", "none", required=True))
    assert report.ok and report.as_json()["verdict"] == "pass"
    report.strict = True
    assert not report.ok and report.unavailable_required == ["b"]
    with pytest.raises(ValueError):
        Check("c", "maybe", "c.x", "")


def test_the_guard_refuses_every_dial_and_restores_socket(dials):
    before = (socket.getaddrinfo, socket.create_connection, socket.socket.connect)
    with no_network():
        for attempt in (
            lambda: socket.getaddrinfo("example.com", 443),
            lambda: socket.create_connection(("example.com", 443)),
            lambda: socket.gethostbyname("example.com"),
        ):
            with pytest.raises(NetworkRefused):
                attempt()
        sock = socket.socket()
        try:
            with pytest.raises(NetworkRefused):
                sock.connect(("127.0.0.1", 9))
        finally:
            sock.close()
    assert (socket.getaddrinfo, socket.create_connection, socket.socket.connect) == before
    assert dials == []  # the guard refused before anything reached the socket layer


def test_a_check_that_dials_is_reported_not_tried(room, capsys, dials, monkeypatch):
    import urllib.request

    from opentine import _verify_offline

    real = _verify_offline.digest_check

    def dialling(path):
        urllib.request.urlopen("https://rekor.sigstore.dev/api/v1/log", timeout=1)
        return real(path)

    monkeypatch.setattr(_verify_offline, "digest_check", dialling)
    code, doc = _report(capsys, "source.tine")
    assert code == 1 and _check(doc, "network")["reason"] == "offline.network-refused"
    assert dials == []
    _validate(doc)


def test_default_verify_output_is_unchanged(room, capsys):
    code, out = _invoke(capsys, "verify", "source.tine")
    assert code == 0 and re.fullmatch(r"OK \S*source\.tine sha256:[0-9a-f]{12}\s*", out)
    code, out = _invoke(capsys, "verify", "source.tine", "--json")
    doc = json.loads(out)
    assert code == 0 and "schema" not in doc and "checks" not in doc
    assert set(doc) == {
        "command",
        "path",
        "ok",
        "integrity",
        "signature_present",
        "signature_checked",
        "signature",
    }


@pytest.mark.parametrize("flag", [["--strict"], ["--report", "r.json"], ["--action-policy", "p"]])
def test_offline_only_flags_are_refused_without_offline(room, capsys, flag):
    code, out = _invoke(capsys, "verify", "source.tine", *flag)
    assert code == 1 and flag[0] in out and "no effect" in out
    assert not (room / "r.json").exists()


def test_receipt_flags_without_attestation_are_refused_offline(room, capsys):
    code, out = _invoke(capsys, "verify", "source.tine", "--offline", "--rekor-key", "k.pem")
    assert code == 1 and "--rekor-key" in out and "no effect" in out


def test_action_policy_is_checked_offline(room, capsys):
    (room / "policy.toml").write_text('[[rule]]\nid = "no-rm"\nprogram = "rm"\n', encoding="utf-8")
    code, doc = _report(capsys, "source.tine", "--action-policy", "policy.toml")
    policy = _check(doc, "action-policy")
    assert code == 0 and policy["outcome"] == "pass" and policy["reason"] == "policy.ok"
    assert re.search(r"sha256 [0-9a-f]{64}", policy["trust_basis"])
    assert _check(doc, "action-manifest")["reason"] == "actions.absent"


@needs_ed25519
def test_attestation_and_absent_receipt_offline(room, capsys, dials):
    argv = ("export", "ed.tine", "--format", "intoto", "--ed25519-key-file", "ed.hex")
    code, _ = _invoke(capsys, *argv, "--output", "a.intoto.jsonl")
    assert code == 0
    code, doc = _report(capsys, "ed.tine", "--pubkey", "ed.pub", "--attestation", "a.intoto.jsonl")
    attestation = _check(doc, "attestation")
    assert code == 0 and attestation["outcome"] == "pass", attestation
    assert attestation["trust_basis"].startswith("supplied key sha256:")
    assert _check(doc, "rekor-receipt")["reason"] == "receipt.absent"
    assert _check(doc, "certificate")["outcome"] == "not-applicable"
    code, doc = _report(
        capsys,
        "ed.tine",
        "--pubkey",
        "ed.pub",
        "--attestation",
        "a.intoto.jsonl",
        "--require-receipt",
    )
    assert code == 1 and _check(doc, "rekor-receipt")["outcome"] == "fail"
    assert dials == []
    _validate(doc)
