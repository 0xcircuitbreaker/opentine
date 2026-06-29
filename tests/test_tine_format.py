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
    # Re-saving a loaded v1 artifact upgrades it to v2 in place, preserving run
    # identity, graph order, and content-addressed step ids, while recording a
    # migration breadcrumb. (v1 still verifies under v1: asserted above.)
    resaved_data = json.loads(resaved.read_text(encoding="utf-8"))
    assert resaved_data["format_version"] == 2
    assert resaved_data["run_id"] == original_data["run_id"]
    assert resaved_data["graph"]["order"] == original_data["graph"]["order"]
    assert set(resaved_data["graph"]["steps"]) == set(original_data["graph"]["steps"])
    assert resaved_data["metadata"]["migration"][-1]["to"] == 2

    forked = run.fork(run.steps[1].id, new_run_id="golden-fork")
    forked.add_step(StepKind.done, {"text": "forked result"})
    diff = run.diff(forked)

    assert len(forked.steps) == 3
    assert diff.common_ancestor == run.steps[1].id
    assert diff.only_a == [run.steps[2]]
    assert diff.only_b == [forked.steps[-1]]
