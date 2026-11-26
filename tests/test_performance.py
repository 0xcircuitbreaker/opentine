"""CI-sized smoke test for .tine graph operations on a 500-step run.

It asserts results only: a wall-clock bound fails on a loaded runner (the repo
rule bans them); scripts/bench and the bench workflow track speed."""

from __future__ import annotations

from opentine import Run, RunStatus, StepKind


def test_ci_sized_graph_save_load_fork_and_diff(tmp_path):
    run = Run(id="perf-smoke", model_info="mock-perf")
    for idx in range(500):
        run.add_step(StepKind.think, {"text": f"step {idx}", "payload": "x" * 20})
    run.status = RunStatus.completed

    path = run.save(tmp_path / "perf.tine")
    loaded = Run.load(path)
    forked = loaded.fork(loaded.steps[249].id, new_run_id="perf-fork")
    forked.add_step(StepKind.done, {"text": "alternate end"})
    diff = loaded.diff(forked)

    assert Run.verify_integrity(path).ok
    assert len(loaded.steps) == 500
    assert len(forked.steps) == 251
    assert diff.common_ancestor == loaded.steps[249].id
