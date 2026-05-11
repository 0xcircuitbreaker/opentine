"""Golden fixture coverage for the current .tine v1 format."""

from __future__ import annotations

import json
from pathlib import Path

from opentine import Run, StepKind

FIXTURES = Path(__file__).parent / "fixtures"


def test_golden_v1_load_save_fork_and_diff(tmp_path):
    fixture = FIXTURES / "golden_v1.tine"
    original_data = json.loads(fixture.read_text(encoding="utf-8"))

    integrity = Run.verify_integrity(fixture)
    assert integrity.ok
    assert integrity.algorithm == "sha256"

    run = Run.load(fixture)
    assert run.id == "golden-v1"
    assert run.model_info == "mock-golden"
    assert [step.kind for step in run.steps] == [StepKind.think, StepKind.tool, StepKind.done]
    assert run.refs["main"] == run.steps[-1].id

    resaved = tmp_path / "resaved.tine"
    run.save(resaved)
    assert Run.verify_integrity(resaved).ok
    assert json.loads(resaved.read_text(encoding="utf-8")) == original_data

    forked = run.fork(run.steps[1].id, new_run_id="golden-fork")
    forked.add_step(StepKind.done, {"text": "forked result"})
    diff = run.diff(forked)

    assert len(forked.steps) == 3
    assert diff.common_ancestor == run.steps[1].id
    assert diff.only_a == [run.steps[2]]
    assert diff.only_b == [forked.steps[-1]]
