"""0.45.1: the redaction follow-ups deferred from 0.45.0.

The ruleset as data (``tine redact rules``), ``tine redact verify`` and the
59-redaction-report conformance family in Python and the pyz, the exit codes of
``tine redact check``, the new schemas (and the Agent Trace export held to
``agent-trace-0.1``), and ``tine schema validate`` on over-deep documents.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _redact_rules, _schemas, cli, redaction
from opentine._cli_errors import NOT_FOUND, USAGE, VERIFICATION_FAILED
from opentine._pyz import _redactr
from opentine._pyz_build import build_bytes
from opentine._redact_report import ReportError, check
from opentine.graph import Run, StepKind
from opentine.policies import PolicySet
from opentine.repository import Repo

ROOT = Path(__file__).resolve().parents[1]
FAMILY = ROOT / "docs" / "conformance" / "vectors" / "59-redaction-report.json"
FAKE = "sk-proj-" + "Zq7Xw2Lr9Tb4Nc8Vm1Hs6Jd3Kf5Gp0Ya"
SEED = bytes(range(32))
pytestmark = pytest.mark.filterwarnings("ignore::opentine._key_store.PlaintextKeyWarning")


def _tine(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return code, capsys.readouterr().out


@pytest.fixture
def dirty(tmp_path, monkeypatch) -> Repo:
    """A repository whose run reaches one blob the current ruleset would still change."""
    from opentine import _push_gate

    repo = Repo.init(tmp_path / "store")
    run = Run(id="dirty", model_info="m", user_prompt="p", policies=PolicySet().to_dict())
    run.add_step(StepKind.done, {"text": "hello"})
    repo.put_run(run, ref="heads/main")
    blob = repo.put("blob", f"key {FAKE}".encode(), redact=False)
    original = _push_gate.reachable
    monkeypatch.setattr(_push_gate, "reachable", lambda *a, **k: [*original(*a, **k), blob])
    return repo


def _keys(tmp_path: Path) -> tuple[Path, Path]:
    private = Ed25519PrivateKey.from_private_bytes(SEED)
    key = tmp_path / "k.key"
    key.write_text(SEED.hex() + "\n", encoding="utf-8")
    pub = tmp_path / "k.pub"
    pub.write_text(private.public_key().public_bytes_raw().hex() + "\n", encoding="utf-8")
    return key, pub


# --- (1) the ruleset as data ----------------------------------------------- #


def test_every_redaction_step_has_exactly_one_published_rule():
    assert len(_redact_rules.RULES) == len(redaction.STEPS)
    ids = [rule_id for rule_id, _, _ in _redact_rules.RULES]
    assert len(ids) == len(set(ids))


def test_redact_rules_json_is_versioned_and_stable(capsys):
    code, out = _tine(capsys, "redact", "rules", "--json")
    document = json.loads(out)
    assert code == 0 and document["command"] == "redact-rules"
    assert document["schema"] == "tine-redaction-rules/1"
    assert document["ruleset"] == "opentine-redaction/2"
    assert document["digest"] == _redact_rules.export()["digest"]
    assert _schemas.validate(document) == ("tine-redaction-rules-1", [])
    assert "sk" in document["token_prefixes"]


# --- (4) exit codes --------------------------------------------------------- #


def test_redact_check_exits_4_on_findings_and_3_on_a_missing_run(dirty, capsys):
    code, out = _tine(capsys, "redact", "check", "--repo", str(dirty.path), "--json")
    body = json.loads(out)
    assert code == VERIFICATION_FAILED and body["clean"] is False
    assert body["command"] == "redact-check" and FAKE not in out
    code, out = _tine(capsys, "redact", "check", "--repo", str(dirty.path), "--run", "nope",
                      "--json")  # fmt: skip
    assert code == NOT_FOUND and json.loads(out)["error"]["code"] == "not_found"


# --- (2) tine redact verify -------------------------------------------------- #


def test_redact_verify_checks_signed_reports_and_refuses_a_tampered_one(dirty, tmp_path, capsys):
    key, pub = _keys(tmp_path)
    out_file = tmp_path / "reports.json"
    _tine(capsys, "redact", "check", "--repo", str(dirty.path), "--ed25519-key-file", str(key),
          "--out", str(out_file))  # fmt: skip
    code, out = _tine(capsys, "redact", "verify", str(out_file), "--pubkey", str(pub), "--json")
    body = json.loads(out)
    assert code == 0 and body["ok"], body
    assert body["reports"][0]["state"] == "verified" and body["reports"][0]["findings"] == 1
    reports = json.loads(out_file.read_text("utf-8"))
    reports[0]["findings"] = []
    reports[0]["clean"] = True
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(reports), encoding="utf-8")
    code, out = _tine(capsys, "redact", "verify", str(forged), "--pubkey", str(pub), "--json")
    row = json.loads(out)["reports"][0]
    assert code == VERIFICATION_FAILED and row["reason"] == "redaction-report.bad-signature"
    code, _ = _tine(capsys, "redact", "verify", str(tmp_path / "missing.json"))
    assert code == NOT_FOUND


def test_redact_verify_refuses_an_unsigned_report(dirty, tmp_path, capsys):
    out_file = tmp_path / "reports.json"
    _tine(capsys, "redact", "check", "--repo", str(dirty.path), "--out", str(out_file))
    code, out = _tine(capsys, "redact", "verify", str(out_file), "--json")
    assert code == VERIFICATION_FAILED
    assert json.loads(out)["reports"][0]["reason"] == "redaction-report.unsigned"


# --- (2) the conformance family in Python and the pyz ------------------------ #


def _cases() -> list[dict]:
    return json.loads(FAMILY.read_text("utf-8"))["cases"]


def _keys_of(value: dict) -> dict:
    hmac, public = value.get("hmac_key_hex"), value.get("public_key")
    return {
        "hmac_key": bytes.fromhex(hmac) if hmac else None,
        "public_key": bytes.fromhex(public) if public else None,
    }


@pytest.mark.parametrize("verifier", ["python", "pyz"])
def test_the_59_family_agrees_in_python_and_the_pyz(verifier):
    from tests.conformance import tagged

    run, refused = (check, ReportError) if verifier == "python" else (
        _redactr.verify, _redactr.Refused)  # fmt: skip
    cases = _cases()
    assert len(cases) == 12
    for case in cases:
        value = tagged.decode(case["input"]["value"])
        if case["expect"] == "accept":
            assert run(value["report"], **_keys_of(value)) == case["output"], case["id"]
        else:
            with pytest.raises(refused) as caught:
                run(value["report"], **_keys_of(value))
            assert caught.value.code == case["reason"], case["id"]


def test_the_built_pyz_verifies_a_report_file_offline(dirty, tmp_path, capsys):
    key, pub = _keys(tmp_path)
    out_file = tmp_path / "reports.json"
    _tine(capsys, "redact", "check", "--repo", str(dirty.path), "--ed25519-key-file", str(key),
          "--out", str(out_file))  # fmt: skip
    report = tmp_path / "report.json"
    report.write_text(json.dumps(json.loads(out_file.read_text("utf-8"))[0]), encoding="utf-8")
    pyz = tmp_path / "tine-verify.pyz"
    pyz.write_bytes(build_bytes())
    argv = [sys.executable, "-I", "-S", pyz.as_posix(), report.as_posix(), "--pubkey",
            pub.as_posix()]  # fmt: skip
    done = subprocess.run(argv, capture_output=True, text=True, timeout=300, cwd=tmp_path)
    result = json.loads(done.stdout)
    assert done.returncode == 0 and result["mode"] == "redaction-report", done.stderr
    assert result["checks"][0]["reason"] == "redaction-report.verified"
    body = json.loads(report.read_text("utf-8"))
    report.write_text(json.dumps({**body, "objects": body["objects"] + 1}), encoding="utf-8")
    done = subprocess.run(argv, capture_output=True, text=True, timeout=300, cwd=tmp_path)
    assert done.returncode == 1
    assert json.loads(done.stdout)["checks"][0]["reason"] == "redaction-report.bad-signature"


# --- (3) schemas ------------------------------------------------------------- #


def test_the_report_schema_holds_the_pinned_reports_and_detects_them():
    for case in _cases():
        if case["expect"] == "accept":
            from tests.conformance import tagged

            report = tagged.decode(case["input"]["value"])["report"]
            assert _schemas.validate(report) == ("opentine-redaction-report-1", [])
    bad = {"kind": "opentine.redaction-report", "report_version": 1}
    assert _schemas.validate(bad)[1]


def test_the_agent_trace_export_validates_against_agent_trace_0_1(tmp_path, monkeypatch):
    from opentine._agent_trace import ROOT_MARKER
    from tests.test_agent_trace_0_19 import _run as trace_run

    monkeypatch.chdir(tmp_path)
    (tmp_path / ROOT_MARKER).mkdir()
    saved = tmp_path / "run.tine"
    trace_run(tmp_path).save(saved)
    out = tmp_path / "trace.json"
    cli.main(["export", str(saved), "--format", "agent-trace", "--output", str(out)])
    record = json.loads(out.read_text("utf-8"))
    assert record["files"], record
    assert _schemas.validate(record, "agent-trace-0.1") == ("agent-trace-0.1", [])
    record["files"][0]["path"] = 7
    assert _schemas.validate(record, "agent-trace-0.1")[1]


# --- (5) over-deep documents ------------------------------------------------- #


@pytest.mark.parametrize("depth", [600, 100_000])
def test_schema_validate_refuses_an_over_deep_document_cleanly(tmp_path, capsys, depth):
    deep = tmp_path / "deep.json"
    deep.write_text("[" * depth + "]" * depth, encoding="utf-8")
    code, out = _tine(capsys, "schema", "validate", str(deep), "--schema", "tine-run-1", "--json")
    error = json.loads(out)["error"]
    assert code == USAGE and error["code"] == "usage" and "deeper than" in error["message"]


def test_schema_validate_still_reads_a_document_at_the_depth_bound(tmp_path, capsys):
    nested = tmp_path / "nested.json"
    nested.write_text("[" * 400 + "]" * 400, encoding="utf-8")
    code, out = _tine(capsys, "schema", "validate", str(nested), "--schema", "tine-run-1", "--json")
    assert code in (0, VERIFICATION_FAILED) and json.loads(out)["command"] == "schema-validate"
