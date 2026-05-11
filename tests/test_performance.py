"""CI-sized performance smoke tests for .tine graph operations."""

from __future__ import annotations

import time

from opentine import Run, RunStatus, StepKind


def test_ci_sized_graph_save_load_fork_and_diff(tmp_path):
    run = Run(id="perf-smoke", model_info="mock-perf")
    for idx in range(500):
        run.add_step(StepKind.think, {"text": f"step {idx}", "payload": "x" * 20})
    run.status = RunStatus.completed

    start = time.perf_counter()
    path = run.save(tmp_path / "perf.tine")
    loaded = Run.load(path)
    forked = loaded.fork(loaded.steps[249].id, new_run_id="perf-fork")
    forked.add_step(StepKind.done, {"text": "alternate end"})
    diff = loaded.diff(forked)
    elapsed = time.perf_counter() - start

    assert Run.verify_integrity(path).ok
    assert len(loaded.steps) == 500
    assert len(forked.steps) == 251
    assert diff.common_ancestor == loaded.steps[249].id
    assert elapsed < 10.0
