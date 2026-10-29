"""0.14.1 footprint: a recorder burst packs its own objects; ``gc --upgrade`` is linear.

Bytes are 4 KiB-rounded file sizes from ``os.walk`` (see
``test_footprint_budget_0_14``). Work is counted in calls, not wall-clock.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from opentine import Recorder, TraceEvent
from opentine.repository import Repo, _run_delta
from opentine.repository._gc import gc
from opentine.repository._gc_prune import plan
from opentine.repository._gc_tidy import loose_entries

BLOCK = 4096
#: 0.14.1 measured (Linux, zlib, threshold 32) a 100-event burst at 220 KiB live
#: and 52-60 KiB finalized; 0.14.0 kept it all loose: 1.6 MiB live and finalized.
BUDGET_BURST_LIVE = 300 * 1024
BUDGET_BURST_FINAL = 100 * 1024


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "32")


def _blocks(root: Path) -> int:
    total = 0
    for directory, _, files in os.walk(root):
        for name in files:
            size = os.lstat(os.path.join(directory, name)).st_size
            total += -(-size // BLOCK) * BLOCK
    return total


def _event(index: int) -> TraceEvent:
    return TraceEvent(
        kind="tool",
        timestamp=index + 1.0,
        trace_id="t",
        span_id=f"s{index}",
        actor="read_file",
        inputs={"path": f"src/{index}.py"},
        outputs={"text": f"line {index}\n" * 20},
    )


def _record(repo, count: int) -> tuple[Recorder, list[str], int]:
    rec = Recorder.start(repo, ref="heads/main", prompt="burst", capture=False)
    ids, peak = [], 0
    for index in range(count):
        ids.append(rec.append(_event(index)))
        if index % 10 == 9:
            peak = max(peak, _blocks(repo.path))
    return rec, ids, peak


@pytest.mark.parametrize("upgrade", [False, True], ids=["v2", "v3"])
def test_burst_session_stays_under_budget(tmp_path, upgrade):
    repo = Repo.init(tmp_path / "burst", compression="zlib")
    if upgrade:
        gc(repo, upgrade=True)
    rec, ids, peak = _record(repo, 100)  # all within seconds: nothing is cold
    assert os.listdir(repo.path / "packs"), "a burst packs its own objects"
    head = rec.run_id
    rec.finalize()
    final = _blocks(repo.path)
    print(f"burst: peak {peak} B, finalized {final} B")
    assert peak <= BUDGET_BURST_LIVE, peak
    assert final <= BUDGET_BURST_FINAL, final
    # Readers see exactly what they did: every snapshot and event, by id.
    fresh = Repo.open(repo.path)
    assert fresh.get(fresh.read_ref("heads/main")).payload()["events"] == ids
    assert fresh.get(head).payload()["events"] == ids
    for oid in ids:
        assert fresh.get(oid).object_type == "event"


def test_burst_packs_are_young_for_prune(tmp_path):
    # Packing is not deleting: superseded snapshots of a live session stay out
    # of prune's reach, their pack being as young as the session.
    repo = Repo.init(tmp_path / "young", compression="zlib")
    _record(repo, 80)
    result = plan(repo, min_age=0)
    assert result.unreachable > 0 and not result.candidates


def test_burst_never_packs_a_version_1_repository(tmp_path):
    repo = Repo.init(tmp_path / "v1", compression=None)
    _record(repo, 80)
    assert not (repo.path / "packs").exists() or not os.listdir(repo.path / "packs")
    assert sum(1 for _ in loose_entries(repo.path)) > 80


def test_hot_packing_is_for_the_recorder_only(tmp_path):
    from opentine.repository import _autopack

    repo = Repo.init(tmp_path / "puts", compression="zlib")
    for index in range(70):
        repo.put("blob", f"blob {index}".encode())
    _autopack.after_write(repo)  # put_run / annotate: cold objects only
    assert not (repo.path / "packs").exists() or not os.listdir(repo.path / "packs")


def test_gc_upgrade_work_is_linear_in_snapshots(tmp_path, monkeypatch):
    # 0.14.0 rebuilt each delta chain from its block's start on read-back and
    # parsed every snapshot three times on write: 1120 applies for 64 events.
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "0")
    repo = Repo.init(tmp_path / "up", compression="zlib")
    rec = Recorder.start(repo, ref="heads/main", prompt="up", capture=False)
    events = 64
    for index in range(events):
        rec.append(_event(index))
    rec.finalize()
    calls = {"apply": 0, "parse": 0}
    apply, parse = _run_delta.apply_delta, _run_delta._parse

    def counted_apply(*args, **kwargs):
        calls["apply"] += 1
        return apply(*args, **kwargs)

    def counted_parse(*args, **kwargs):
        calls["parse"] += 1
        return parse(*args, **kwargs)

    monkeypatch.setattr(_run_delta, "apply_delta", counted_apply)
    monkeypatch.setattr(_run_delta, "_parse", counted_parse)
    gc(repo, upgrade=True)
    snapshots = events + 2  # start, one per append, finalize
    assert calls["apply"] <= 2 * snapshots, calls  # one write check, one read-back
    assert calls["parse"] <= 5 * (snapshots + events), calls
    fresh = Repo.open(repo.path)
    assert len(fresh.get(fresh.read_ref("heads/main")).payload()["events"]) == events


def test_read_memo_keeps_the_delta_depth_limit():
    # A base rebuilt earlier still counts its own deltas: reading in order must
    # refuse a chain past MAX_DELTA_DEPTH exactly as a cold read does.
    from opentine.kernel import KernelError, ObjectEnvelope
    from opentine.repository._pack_v3 import resolve
    from opentine.repository._packs import oid_of

    events = [f"event-{index}" for index in range(40)]
    base = ObjectEnvelope.create("run", {"events": events[:-1], "status": "running"}).encode()
    target = ObjectEnvelope.create("run", {"events": events, "status": "running"}).encode()
    base_oid, oid = oid_of(base), oid_of(target)
    delta = _run_delta.run_delta(target, base)
    assert delta is not None

    def stored(key):
        assert key == oid
        return delta, _run_delta.RUN_DELTA, len(target), base_oid

    deepest = _run_delta.MAX_DELTA_DEPTH
    assert resolve(oid, stored, {base_oid: (base, deepest - 1)}) == target
    with pytest.raises(KernelError, match="too deep"):
        resolve(oid, stored, {base_oid: (base, deepest)})
