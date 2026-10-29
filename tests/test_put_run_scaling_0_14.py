"""put_run must not re-validate every object in the repository on each write.

Writing N runs used to cost O(N^2): every put listed and path-validated each
annotation (and every fan-out directory) several times. Counted, not timed: the
directory entries enumerated and confined paths built by put #60 must stay
close to those of put #20, where a full rescan would triple them.
"""

from __future__ import annotations

import os

from opentine import Run, RunStatus, StepKind
from opentine.repository import Repo, _dir_cache, _objects, _paths


def _run(index: int) -> Run:
    run = Run(id=f"scale-{index}", model_info="mock-scale")
    for step in range(3):
        run.add_step(StepKind.tool, {"prompt": f"same {step}", "out": "tool output"})
    run.status = RunStatus.completed
    if index % 25 == 7:
        run = run.fork(run.steps[1].id, new_run_id=f"scale-fork-{index}")
        run.add_step(StepKind.done, {"index": index})
    return run


def test_put_run_cost_does_not_grow_with_repository_size(tmp_path, monkeypatch):
    # Trust a cached listing as soon as its fingerprint matches, so the count is
    # independent of how fast the filesystem clock ticks on this machine.
    monkeypatch.setattr(_dir_cache, "_RACY_SECONDS", -1.0)
    monkeypatch.setattr(_dir_cache, "_CACHE", {})
    counts = {"entries": 0, "paths": 0}
    children, internal = _objects._children, _paths.internal_path

    def counted_children(directory):
        for entry in children(directory):
            counts["entries"] += 1
            yield entry

    def counted_internal(root, *parts):
        counts["paths"] += 1
        return internal(root, *parts)

    monkeypatch.setattr(_objects, "_children", counted_children)
    monkeypatch.setattr(_objects, "internal_path", counted_internal)
    repo = Repo.init(tmp_path / "repo")
    measured = {}
    for index in range(61):
        before = dict(counts)
        repo.put_run(_run(index))
        if index in (20, 60):
            measured[index] = {key: counts[key] - before[key] for key in counts}
    early, late = measured[20], measured[60]
    assert late["entries"] <= early["entries"] * 1.5 + 64, measured
    assert late["paths"] <= early["paths"] * 1.5 + 16, measured


def test_cached_listing_rescans_after_a_change(tmp_path, monkeypatch):
    monkeypatch.setattr(_dir_cache, "_RACY_SECONDS", -1.0)
    monkeypatch.setattr(_dir_cache, "_CACHE", {})
    calls = []

    def scan():
        calls.append(1)
        return tuple(sorted(os.listdir(tmp_path)))

    assert _dir_cache.cached(tmp_path, scan) == ()
    assert _dir_cache.cached(tmp_path, scan) == ()
    assert len(calls) == 1
    (tmp_path / "new").write_bytes(b"")
    stat = os.stat(tmp_path)
    os.utime(tmp_path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 10**9))
    assert _dir_cache.cached(tmp_path, scan) == ("new",)
    assert len(calls) == 2
