"""0.44: cost aggregates as OTLP metrics and as a signed tine-cost-statement/1."""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest

import opentine.cli as cli
from opentine import _cost_export
from opentine._signing_keys import generate_ed25519
from opentine.core import Run, RunStatus, StepKind


def _run() -> Run:
    run = Run(id="cost_run", model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.model, {"text": "a"}, {"text": "b"}, usage={"input": 9, "output": 3})
    run.add_step(StepKind.tool, {"name": "grep", "arguments": {}}, {"text": "hit"})
    run.status = RunStatus.completed
    return run


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    _run().save(tmp_path / "run.tine")
    private, public = generate_ed25519()
    (tmp_path / "k.hex").write_text(private, encoding="ascii")
    (tmp_path / "k.pub").write_text(public, encoding="ascii")
    other, other_public = generate_ed25519()
    (tmp_path / "other.pub").write_text(other_public, encoding="ascii")
    return tmp_path


def test_otlp_metrics_carry_tokens_and_cost(room):
    cli.main(["cost", "run.tine", "--otlp", "m.json"])
    document = json.loads((room / "m.json").read_text())
    (resource,) = document["resourceMetrics"]
    attributes = {a["key"]: a["value"]["stringValue"] for a in resource["resource"]["attributes"]}
    assert attributes["opentine.run.id"] == "cost_run"
    metrics = {m["name"]: m for m in resource["scopeMetrics"][0]["metrics"]}
    tokens = metrics["gen_ai.client.token.usage"]["sum"]
    assert tokens["aggregationTemporality"] == 2 and tokens["isMonotonic"]
    by_type = {p["attributes"][0]["value"]["stringValue"]: p["asInt"] for p in tokens["dataPoints"]}
    assert by_type == {"input": "9", "output": "3"}
    assert metrics["opentine.cost.usd"]["unit"] == "USD"


def test_signed_statement_round_trips_and_detects_tampering(room, capsys):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cli.main(["cost", "run.tine", "--statement", "s.json", "--sign-key", "k.hex"])
    doc = json.loads((room / "s.json").read_text())
    assert doc["schema"] == _cost_export.SCHEMA
    assert doc["signature"]["scheme"] == "tine-sig/3"
    capsys.readouterr()

    cli.main(["cost", "run.tine", "--verify-statement", "s.json", "--pubkey", "k.pub"])
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] and result["matches_run"] and result["signature"] == "verified"

    with pytest.raises(SystemExit) as wrong_key:
        cli.main(["cost", "run.tine", "--verify-statement", "s.json", "--pubkey", "other.pub"])
    assert wrong_key.value.code == 4
    capsys.readouterr()

    doc["aggregate"]["total_cost"] = 0.0 if doc["aggregate"]["total_cost"] else 1.0
    (room / "t.json").write_text(json.dumps(doc))
    with pytest.raises(SystemExit):
        cli.main(["cost", "run.tine", "--verify-statement", "t.json", "--pubkey", "k.pub"])
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False and result["matches_run"] is False


def test_statement_needs_a_key_and_unsigned_never_verifies(room):
    with pytest.raises(SystemExit):
        cli.main(["cost", "run.tine", "--statement", "s.json"])
    with pytest.raises(SystemExit):
        cli.main(["cost", "run.tine", "--sign-key", "k.hex"])
    result = _cost_export.verify_statement(_cost_export.statement(_run()), _run())
    assert result == {"ok": False, "matches_run": True, "signature": "unsigned", "basis": None}
