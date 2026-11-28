"""0.91: halting hostile process trees, signed stop-compliance records and the oversight queue.

The children here ignore what they are told and spawn children of their own;
the tests wait on pipes (ordering evidence) and move an injected clock, never
on elapsed time.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from opentine import _oversight_queue, _stop_compliance, _stop_policy
from opentine._stop_runner import StopRunner
from opentine._stop_supervise import _alive
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401 - autouse
from tests.stop_helpers import OTHER, RUNNER, Clock, fleet, keep_going, key

HOSTILE = """\
import os, signal, subprocess, sys, time
if os.name != "nt":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
escape = {"start_new_session": True} if sys.platform.startswith("linux") else {}
child = subprocess.Popen([sys.executable, "-c", "import time\\nwhile True: time.sleep(0.5)"],
                         **escape)
sys.stdout.write(f"{child.pid}\\n")
sys.stdout.flush()
while True:
    time.sleep(0.5)
"""


def runner(tmp_path: Path, clock: Clock, seed: str = RUNNER) -> StopRunner:
    channel, (repo,) = fleet(tmp_path)
    keep_going(repo, channel, ["r"], clock)
    return StopRunner(repo, _stop_policy.load(repo), "r", key(seed), clock_ms=clock)


def hostile(tmp_path: Path, stop: StopRunner) -> tuple[subprocess.Popen, int]:
    script = tmp_path / "hostile.py"
    script.write_bytes(HOSTILE.encode("utf-8"))
    process = stop.supervised.launch([sys.executable, script.as_posix()], dict(os.environ),
                                     stdout=subprocess.PIPE)  # fmt: skip
    grandchild = int(process.stdout.readline())  # the tree exists before the halt
    return process, grandchild


def test_a_stale_proof_kills_the_whole_tree_and_signs_a_compliant_record(tmp_path):
    clock = Clock()
    stop = runner(tmp_path, clock)
    stop.preflight()
    process, grandchild = hostile(tmp_path, stop)
    assert stop.supervised.admit() is None
    clock.advance(301)
    halt = stop.supervised.admit()
    assert halt is not None and halt.code == "stop.continue-stale"
    process.wait()
    process.stdout.close()
    done = stop.finish()
    claim = done["claim"]
    assert claim["code"] == "stop.continue-stale" and claim["compliant"] is True
    assert claim["residual_processes"] == 0 and claim["forwarded_after_stop"] == 0
    assert claim["refused_after_stop"] == 1 and claim["time_to_halt_ms"] == 0
    if sys.platform.startswith("linux"):
        assert not _alive(grandchild)  # it left the process group and still went
    assert _stop_compliance.check(stop.repo, done["record"]) is None
    assert _stop_compliance.items(stop.repo) == []


def test_every_action_after_the_halt_is_refused(tmp_path):
    clock = Clock()
    stop = runner(tmp_path, clock)
    clock.advance(301)
    assert [stop.supervised.admit().code for _ in range(3)] == ["stop.continue-stale"] * 3
    assert stop.supervised.refused_after == 3


def test_a_non_compliant_halt_goes_to_the_oversight_queue(tmp_path):
    clock = Clock()
    stop = runner(tmp_path, clock)
    clock.advance(301)
    stop.supervised.admit()
    stop.supervised.note_forwarded()  # an action that got through after the halt
    done = stop.finish()
    assert done["claim"]["compliant"] is False
    item = f"stop:{done['record']}"
    assert item in {row["item"] for row in _oversight_queue._sources(stop.repo)}
    assert "non-compliant" in _stop_compliance.check(stop.repo, done["record"])


def test_a_record_not_signed_by_a_pinned_runner_is_flagged(tmp_path):
    clock = Clock()
    stop = runner(tmp_path, clock, seed=OTHER)
    clock.advance(301)
    stop.supervised.admit()
    done = stop.finish()
    assert done["claim"]["compliant"] is True
    assert "runner" in _stop_compliance.check(stop.repo, done["record"])
    assert [r["item"] for r in _stop_compliance.items(stop.repo)] == [f"stop:{done['record']}"]


def test_a_compliance_record_is_held_for_good(tmp_path):
    from opentine.repository._holds import HoldError, release

    clock = Clock()
    stop = runner(tmp_path, clock)
    clock.advance(301)
    stop.supervised.admit()
    done = stop.finish()
    with pytest.raises(HoldError, match="never released"):
        release(stop.repo, done["record"])
    with pytest.raises(HoldError, match="never released"):
        release(stop.repo, "stop-policy:fleet-a")


def test_a_fleet_stop_measures_time_since_the_stop(tmp_path):
    from tests.stop_helpers import halt_fleet

    clock = Clock()
    stop = runner(tmp_path, clock)
    halt_fleet(stop.repo, Path(stop.policy["channel"]), clock)
    clock.advance(400)  # the runner only looked again after the window
    assert stop.supervised.admit().code == "stop.stopped"
    claim = stop.finish()["claim"]
    assert claim["since_stop_ms"] == 400_000 and claim["compliant"] is False
