"""0.14 Footprint: post-write auto-pack, per-session reflog rows, gc/du accounting."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from opentine import Recorder, Run, TraceEvent
from opentine.graph import StepKind
from opentine.kernel import KernelError
from opentine.repository import Repo, _autopack
from opentine.repository._du import usage
from opentine.repository._fanout_tidy import GRACE, tidy_fanouts
from opentine.repository._gc import gc
from opentine.repository._gc_tidy import loose_entries
from opentine.repository._reflog import read_reflog


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")


def _repo(tmp_path, name="r") -> Repo:
    return Repo.init(tmp_path / name, compression="zlib")


def _run(index: int, steps: int = 4) -> Run:
    run = Run(id=f"r{index}")
    for step in range(steps):
        run.add_step(
            StepKind.tool,
            {"name": "Bash", "arguments": {"command": f"ls {index} {step}"}},
            outputs={"result": f"out {index} {step} " * 20},
        )
    return run


def _event(index: int) -> TraceEvent:
    return TraceEvent(
        kind="tool",
        timestamp=index + 1.0,
        trace_id="t",
        span_id=f"s{index}",
        actor="read_file",
        inputs={"n": index},
        outputs={"text": f"body {index} " * 30},
    )


def _age(repo, seconds: float = 120.0) -> None:
    stamp = time.time() - seconds
    for _, path, _ in loose_entries(repo.path):
        os.utime(path, (stamp, stamp))


def _packs(repo) -> list[str]:
    return sorted(name for name in os.listdir(repo.path / "packs") if name.endswith(".tpk"))


# -- 1. put_run / fork / annotate auto-pack ---------------------------------------


def test_put_run_autopacks_cold_loose_objects(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "40")
    monkeypatch.setattr(_autopack, "RESCAN_INTERVAL", 0.0)
    repo = _repo(tmp_path)
    for index in range(4):
        repo.put_run(_run(index), ref=f"heads/r{index}")
    assert not _packs(repo)  # nothing cold yet: a live writer's objects stay loose
    _age(repo)
    repo.__dict__["_autopack_writes"] = 10**6  # the write counter crossed the threshold
    result = repo.put_run(_run(9), ref="heads/r9")
    assert _packs(repo)
    assert len(list(loose_entries(repo.path))) < 40  # only the young run is loose
    assert repo.load_run("heads/r0").steps and repo.load_run(result.run_id).steps
    assert repo.fsck().ok


def test_fork_autopacks_too(tmp_path, monkeypatch):
    monkeypatch.setattr(_autopack, "RESCAN_INTERVAL", 0.0)
    repo = _repo(tmp_path)
    result = repo.put_run(_run(1, steps=30), ref="heads/main")
    _age(repo)
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "20")
    repo.__dict__["_autopack_writes"] = 10**6  # as if many objects were written
    events = repo.get(result.run_id).payload()["events"]
    repo.fork(result.run_id, events[3], ref="experiments/f")
    assert _packs(repo)


def test_post_write_hook_is_cheap_below_the_threshold(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "256")
    scans = []
    original = _autopack.old_loose
    monkeypatch.setattr(
        _autopack, "old_loose", lambda *a, **k: scans.append(1) or original(*a, **k)
    )
    repo = _repo(tmp_path)
    for index in range(5):
        repo.put_run(_run(index), ref=f"heads/r{index}")
    assert len(scans) == 1  # one scan per Repo instance, then a write counter


def test_post_write_hook_respects_off(tmp_path, monkeypatch):
    monkeypatch.setattr(_autopack, "RESCAN_INTERVAL", 0.0)
    repo = _repo(tmp_path)
    for index in range(3):
        repo.put_run(_run(index), ref=f"heads/r{index}")
    _age(repo)
    repo.__dict__["_autopack_writes"] = 10**6
    repo.put_run(_run(7), ref="heads/r7")
    assert not _packs(repo)  # OPENTINE_AUTO_PACK=off (fixture)


def test_post_write_hook_never_packs_a_v1_repository(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "5")
    monkeypatch.setattr(_autopack, "RESCAN_INTERVAL", 0.0)
    repo = Repo.init(tmp_path / "v1", compression=None)
    repo.put_run(_run(0), ref="heads/a")
    _age(repo)
    repo.put_run(_run(1), ref="heads/b")
    assert not _packs(repo)
    assert json.loads((repo.path / "config.json").read_text())["version"] == 1


# -- 2./3. the recorder: per-session reflog rows, live auto-pack ---------------------


def test_recorder_logs_session_start_and_finalize_not_every_event(tmp_path):
    repo = _repo(tmp_path)
    rec = Recorder.start(repo, ref="heads/main", prompt="p", capture=False)
    for index in range(12):
        rec.append(_event(index))
        assert repo.read_ref("heads/main") == rec.run_id  # the live view still moves
    final = rec.finalize()
    rows = read_reflog(repo.path, "heads/main")
    assert len(rows) == 2 and rows[0]["new"] == final and rows[-1]["old"] is None  # newest first
    repo.update_ref("heads/main", rows[-1]["new"], expected_old=final)  # explicit moves log
    assert len(read_reflog(repo.path, "heads/main")) == 3


def test_recorder_packs_cold_snapshots_mid_session(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "30")
    monkeypatch.setattr(_autopack, "RESCAN_INTERVAL", 0.0)
    repo = _repo(tmp_path)
    rec = Recorder.start(repo, ref="heads/main", prompt="p", capture=False)
    for index in range(40):
        rec.append(_event(index))
        if index % 10 == 9:
            _age(repo)
    assert _packs(repo)  # packed while the session is still running
    live = repo.get(repo.read_ref("heads/main")).payload()
    assert live["status"] == "running" and len(live["events"]) == 40
    rec.finalize()
    assert len(repo.load_run("heads/main").steps) == 40 and repo.fsck().ok


# -- 3./5. gc and du account for refs, reflogs and fan-out state -------------------


def _tree(root: Path) -> int:
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file())


def test_gc_footprint_counts_refs_and_reflogs(tmp_path):
    repo = _repo(tmp_path)
    for index in range(3):
        repo.put_run(_run(index), ref=f"heads/r{index}")
    result = gc(repo)
    floor = _tree(repo.path / "packs") + _tree(repo.path / "refs") + _tree(repo.path / "logs")
    assert result.bytes_after >= floor


def _fanout(repo, fanout_id: str, statuses: list[str], age: float) -> Path:
    directory = repo.path / "fanouts"
    (directory / fanout_id).mkdir(parents=True)
    (directory / fanout_id / "0.cost").write_text("{}")
    members = [{"key": str(i), "status": status} for i, status in enumerate(statuses)]
    record = directory / f"{fanout_id}.json"
    record.write_text(json.dumps({"id": fanout_id, "members": members}))
    stamp = time.time() - age
    os.utime(record, (stamp, stamp))
    return record


def test_gc_removes_finished_fanout_state_after_its_grace(tmp_path):
    repo = _repo(tmp_path)
    done = _fanout(repo, "a" * 12, ["ok", "failed"], GRACE + 60)
    young = _fanout(repo, "b" * 12, ["ok"], 60)
    running = _fanout(repo, "c" * 12, ["ok", "running"], GRACE + 60)
    (repo.path / "fanouts" / "notes.json").write_text("{}")  # not ours: untouched
    report = usage(repo)
    assert report["fanouts"]["files"] == 7 and report["fanouts"]["bytes"] > 0
    gc(repo)
    assert not done.exists() and not (repo.path / "fanouts" / ("a" * 12)).exists()
    assert young.exists() and running.exists()
    assert (repo.path / "fanouts" / "notes.json").exists()
    assert tidy_fanouts(repo.path) == 0


# -- 4. gc --upgrade on an already-v3 repository ------------------------------------


def test_upgrade_of_a_v3_repository_does_not_repack(tmp_path):
    repo = _repo(tmp_path)
    for index in range(3):
        repo.put_run(_run(index), ref=f"heads/r{index}")
    first = gc(repo, upgrade=True)
    packs = _packs(repo)
    assert first.packed > 0 and len(packs) == 1
    second = gc(repo, upgrade=True)
    assert second.packed == 0 and second.removed_packs == 0 and _packs(repo) == packs
    repo.put_run(_run(5), ref="heads/r5")
    third = gc(repo, upgrade=True)  # loose objects still pack, beside the old pack
    assert third.packed > 0 and third.removed_packs == 0 and len(_packs(repo)) == 2
    assert Repo.open(repo.path).fsck().ok


# -- 6. an explicit path that does not exist never walks up -------------------------


def test_open_of_a_missing_explicit_path_fails(tmp_path):
    _repo(tmp_path, ".")
    with pytest.raises(KernelError, match="does not exist"):
        Repo.open(tmp_path / "typo")
    nested = tmp_path / "sub" / "dir"
    nested.mkdir(parents=True)
    assert Repo.open(nested).path == (tmp_path / ".tine").resolve()


def test_open_default_still_discovers_from_cwd(tmp_path, monkeypatch):
    _repo(tmp_path, ".")
    nested = tmp_path / "deep"
    nested.mkdir()
    monkeypatch.chdir(nested)
    assert Repo.open().path == (tmp_path / ".tine").resolve()
    assert Repo.open(".").path == (tmp_path / ".tine").resolve()
