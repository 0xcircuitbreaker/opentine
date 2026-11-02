"""0.27.0 replay fidelity labels: every replayed step says how it was reproduced."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._graph_types import short_id
from opentine._replay_fidelity import LABELS, Fidelity, classify_cache, classify_rerun


def _run(path: Path, *, secret: bool = False) -> Run:
    run = Run(id="fidelity_source", model_info="mock-model", user_prompt="p")
    first = run.add_step(StepKind.think, {"text": "a"})
    text = "key=[REDACTED]" if secret else "b"
    second = run.add_step(
        StepKind.tool, {"name": "t", "arguments": {"x": text}}, parent_id=first.id
    )
    run.add_step(StepKind.done, {"text": "c"}, parent_id=second.id)
    run.status = RunStatus.completed
    run.save(path)
    return run


@pytest.fixture
def workspace(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _invoke(monkeypatch, capsys, *argv: str) -> tuple[int, str]:
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_label_order_is_documented_strongest_first():
    assert LABELS == ("exact", "recomputed-match", "unavailable", "diverged")
    fid = Fidelity([("a", "exact"), ("b", "unavailable")])
    assert fid.overall == "unavailable"
    assert fid.meets("unavailable") and fid.meets("diverged") and not fid.meets("exact")
    assert Fidelity().overall is None and Fidelity().meets("exact")


def test_cache_verify_json_labels_every_retained_step_exact(workspace, monkeypatch, capsys):
    _run(workspace / "source.tine")
    code, out = _invoke(monkeypatch, capsys, "replay", "source.tine", "--verify", "--json")
    payload = json.loads(out)
    assert code == 0 and payload["ok"] is True
    fid = payload["fidelity"]
    assert fid["overall"] == "exact"
    assert fid["counts"] == {"exact": 3, "recomputed-match": 0, "unavailable": 0, "diverged": 0}
    assert [s["label"] for s in fid["steps"]] == ["exact"] * 3
    assert fid["meets_minimum"] is True and fid["min_fidelity"] is None
    # Existing keys stay stable.
    assert {"structural_drift", "accounting_drift", "slice_ok", "integrity"} <= set(payload)


def test_redacted_step_is_unavailable_and_min_fidelity_gates(workspace, monkeypatch, capsys):
    _run(workspace / "source.tine", secret=True)
    code, out = _invoke(monkeypatch, capsys, "replay", "source.tine", "--verify", "--json")
    assert code == 0
    assert json.loads(out)["fidelity"]["overall"] == "unavailable"
    code, out = _invoke(
        monkeypatch, capsys, "replay", "source.tine", "--verify", "--min-fidelity", "exact"
    )
    assert code == 1
    assert "fidelity below --min-fidelity exact" in _flat(out)
    code, _ = _invoke(
        monkeypatch, capsys, "replay", "source.tine", "--verify", "--min-fidelity", "unavailable"
    )
    assert code == 0


def test_text_outputs_carry_per_step_labels_and_summary(workspace, monkeypatch, capsys):
    run = _run(workspace / "source.tine")
    code, out = _invoke(monkeypatch, capsys, "replay", "source.tine", "--verify")
    assert code == 0
    flat = _flat(out)
    assert "fidelity: exact (exact=3)" in flat
    assert f"{short_id(run.steps[0].id)} exact" in flat
    code, out = _invoke(monkeypatch, capsys, "replay", "source.tine")
    assert code == 0 and "fidelity: exact (exact=3)" in _flat(out)


def test_min_fidelity_without_verify_is_refused(workspace, monkeypatch, capsys):
    _run(workspace / "source.tine")
    code, out = _invoke(monkeypatch, capsys, "replay", "source.tine", "--min-fidelity", "exact")
    assert code == 1 and "--min-fidelity" in out


def test_classifiers_see_missing_changed_and_rerun_divergence(tmp_path):
    source = _run(tmp_path / "a.tine")
    ids = [step.id for step in source.steps]
    partial = Run.load(tmp_path / "a.tine").fork(ids[1], nonce="")
    fid = classify_cache(source, set(ids), partial)
    assert [label for _, label in fid.steps] == ["exact", "exact", "unavailable"]
    other = Run(id="other", model_info="mock-model")
    other.add_step(StepKind.think, {"text": "a"})
    other.add_step(StepKind.think, {"text": "zzz"}, parent_id=other.steps[0].id)
    rerun = classify_rerun(source, other)
    assert [label for _, label in rerun.steps] == ["recomputed-match", "diverged", "diverged"]
    assert rerun.overall == "diverged"
