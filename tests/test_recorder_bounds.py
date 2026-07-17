"""Recorder batching and repository synchronization ceilings."""

from __future__ import annotations

import pytest

from opentine.repository import Repo
from opentine.repository.pack import MAX_PACK_OBJECTS, reachable
from opentine.trace import Recorder, TraceEvent
from opentine.trace import recorder as recorder_module


def _event(index: int, parent: str | None = None) -> TraceEvent:
    return TraceEvent(
        "model",
        float(index),
        "bulk-trace",
        f"span-{index}",
        parent_span_id=parent,
        inputs={"input": index},
        outputs={"output": index},
    )


def test_bulk_import_writes_one_run_snapshot_and_remains_packable(tmp_path):
    repo = Repo.init(tmp_path / "origin")
    recorder = Recorder.start(repo, capture=False)
    runs_before = {oid for oid in repo.iter_oids() if oid.startswith("run:")}
    events = [_event(index, f"span-{index - 1}" if index else None) for index in range(20)]

    ids = recorder.import_events(events)

    runs_after = {oid for oid in repo.iter_oids() if oid.startswith("run:")}
    assert len(runs_after - runs_before) == 1
    assert recorder.payload["events"] == ids
    graph = reachable(repo, [recorder.run_id])
    assert len(graph) <= 3 * len(events) + 16
    assert recorder_module.MAX_RECORDED_EVENTS * 3 + 16 < MAX_PACK_OBJECTS

    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(repo.pack(graph))
    assert clone.has(recorder.run_id)
    assert clone.fsck().ok


def test_event_cap_fails_before_import_or_append_writes(monkeypatch, tmp_path):
    monkeypatch.setattr(recorder_module, "MAX_RECORDED_EVENTS", 1)
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    before = set(repo.iter_oids())
    ref_before = repo.read_ref("heads/main")

    with pytest.raises(ValueError, match="limited to 1 events"):
        recorder.import_events([_event(0), _event(1)])
    assert set(repo.iter_oids()) == before
    assert repo.read_ref("heads/main") == ref_before

    recorder.append(_event(0))
    before = set(repo.iter_oids())
    ref_before = repo.read_ref("heads/main")
    with pytest.raises(ValueError, match="limited to 1 events"):
        recorder.append(_event(1, "span-0"))
    assert set(repo.iter_oids()) == before
    assert repo.read_ref("heads/main") == ref_before
