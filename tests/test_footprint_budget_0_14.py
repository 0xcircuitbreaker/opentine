"""CI size budgets: a deterministic small corpus must stay under fixed byte budgets.

Bytes are each file's size rounded up to a 4 KiB block (what most filesystems
allocate), summed portably from ``os.walk`` -- not ``st_blocks``, which Windows
lacks. Budgets carry about 25% headroom over what 0.14 measured; a regression
that brings back unbounded loose growth (no auto-pack after ``put_run``, a
reflog row per recorded event) blows through them by a wide margin.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from opentine import Recorder, Run, TraceEvent
from opentine.graph import StepKind
from opentine.repository import Repo, _autopack
from opentine.repository._gc import gc
from opentine.repository._gc_tidy import loose_entries

BLOCK = 4096
#: 0.14 measured (Linux, zlib) 468 KiB / 180 KiB for 16 put_run runs loose with
#: auto-pack / after gc (0.13: 1296 KiB loose), and 600 KiB / 92 KiB for a
#: 100-event session live / finalized (0.13: 1672 KiB live).
BUDGET_LOOSE = 600 * 1024
BUDGET_GC = 230 * 1024
BUDGET_LIVE = 768 * 1024
BUDGET_SESSION = 118 * 1024


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "32")
    monkeypatch.setattr(_autopack, "RESCAN_INTERVAL", 0.0, raising=False)


def _blocks(root: Path) -> int:
    total = 0
    for directory, _, files in os.walk(root):
        for name in files:
            size = os.lstat(os.path.join(directory, name)).st_size
            total += -(-size // BLOCK) * BLOCK
    return total


def _age(repo, seconds: float = 120.0) -> None:
    """Make every loose object cold, as if the corpus had been written over minutes."""
    stamp = time.time() - seconds
    for _, path, _ in loose_entries(repo.path):
        os.utime(path, (stamp, stamp))


def _run(index: int) -> Run:
    run = Run(id=f"budget-{index}")
    for step in range(5):
        run.add_step(
            StepKind.tool,
            {"name": "Bash", "arguments": {"command": f"grep -n item{index} src/{step}.py"}},
            outputs={"result": f"src/{step}.py:{index}: item{index} = {step}\n" * 12},
        )
    run.add_step(StepKind.done, {"text": f"finished {index}"})
    return run


def test_put_run_corpus_stays_under_budget(tmp_path):
    repo = Repo.init(tmp_path / "puts", compression="zlib")
    for index in range(16):
        repo.put_run(_run(index), ref=f"heads/run-{index}")
        if index % 4 == 3:
            _age(repo)
    loose = _blocks(repo.path)
    gc(repo)
    packed = _blocks(repo.path)
    print(f"put_run corpus: loose+autopack {loose} B, after gc {packed} B")
    assert loose <= BUDGET_LOOSE, loose
    assert packed <= BUDGET_GC, packed


def test_recorder_session_stays_under_budget(tmp_path):
    repo = Repo.init(tmp_path / "session", compression="zlib")
    rec = Recorder.start(repo, ref="heads/main", prompt="budget", capture=False)
    for index in range(100):
        rec.append(
            TraceEvent(
                kind="tool",
                timestamp=index + 1.0,
                trace_id="t",
                span_id=f"s{index}",
                actor="read_file",
                inputs={"path": f"src/{index}.py"},
                outputs={"text": f"line {index}\n" * 20},
            )
        )
        if index % 25 == 24:
            _age(repo)
    live = _blocks(repo.path)  # mid-session: cold snapshots already packed
    rec.finalize()
    session = _blocks(repo.path)
    print(f"recorder session: live {live} B, finalized {session} B")
    assert live <= BUDGET_LIVE, live
    assert session <= BUDGET_SESSION, session
