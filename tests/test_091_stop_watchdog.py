"""0.91 review: harness, script and fan-out runs are watched and halted as one tree.

Under a stop policy ``tine run`` (script, ``--harness``, ``--parallel``) and
``tine fan-out`` re-run themselves as a supervised child: a watchdog re-checks
the stop channel and the continue proof every ``watchdog_s`` and kills the
whole tree on a stop, a stale proof or an unreachable channel, then signs the
compliance record. The children here are hostile (no model calls, a setsid
grandchild, a cut channel). Clocks are injected in both processes.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from opentine import _stop_compliance, _stop_guard, _stop_supervise, _stop_tree, cli
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401 - autouse
from tests.stop_helpers import RUNNER, STOPPER, Clock, fleet, keep_going, key_file, make_repo
from tests.stop_tree_helpers import CUTS, FORGES, SLEEPS, STOPS, child_clock, dead, script_args

linux = pytest.mark.skipif(not os.path.isdir("/proc/self"), reason="needs /proc")


def tine(*argv) -> int:
    try:
        cli.main([str(a) for a in argv])
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1
    return 0


@pytest.fixture
def fixed(monkeypatch, tmp_path) -> Clock:
    clock = Clock()
    monkeypatch.setattr(_stop_guard, "_now_ms", clock)
    child_clock(tmp_path, monkeypatch, clock())
    monkeypatch.delenv(_stop_tree.SUPERVISED_ENV, raising=False)
    return clock


def _policy_repo(tmp_path, monkeypatch, fixed, count=1):
    channel, repos = fleet(tmp_path, count, watchdog_s=1)
    keep_going(repos[0], channel, ["r"], fixed)
    monkeypatch.chdir(Path(repos[0].path).parent)
    return channel, repos


def _held_claim(repo) -> dict:
    (record,) = _stop_compliance.held(repo)
    return repo.get(record).payload()["claim"]


@linux
def test_a_script_run_with_no_model_calls_is_halted_mid_run_with_its_grandchild(
    tmp_path, monkeypatch, fixed
):
    channel, (repo, other) = _policy_repo(tmp_path, monkeypatch, fixed, 2)
    script, pidfile = tmp_path / "hostile.py", tmp_path / "grandchild.pid"
    script.write_bytes(STOPS.encode())
    script_args(monkeypatch, Path(other.path).parent, channel, STOPPER, pidfile, fixed())
    code = tine("run", script, "--stop-run", "r", "--stop-key",
                key_file(tmp_path, RUNNER, "runner"))  # fmt: skip
    assert code == 3
    assert dead(int(pidfile.read_text()))
    claim = _held_claim(repo)
    assert claim["code"] == "stop.stopped" and claim["residual_processes"] == 0


@linux
def test_a_child_that_cuts_the_channel_halts_the_tree(tmp_path, monkeypatch, fixed):
    channel, (repo,) = _policy_repo(tmp_path, monkeypatch, fixed)
    script, pidfile = tmp_path / "cut.py", tmp_path / "grandchild.pid"
    script.write_bytes(CUTS.encode())
    script_args(monkeypatch, channel, pidfile)
    code = tine("run", script, "--stop-run", "r", "--stop-key",
                key_file(tmp_path, RUNNER, "runner"))  # fmt: skip
    assert code == 3
    assert dead(int(pidfile.read_text()))
    assert _held_claim(repo)["code"] == "stop.channel-unreachable"


@linux
def test_a_proof_that_goes_stale_mid_run_halts_the_tree(tmp_path, monkeypatch, fixed):
    """Only the supervisor's clock moves: its watchdog alone sees the proof go stale."""
    import threading

    channel, (repo,) = _policy_repo(tmp_path, monkeypatch, fixed)
    script, pidfile = tmp_path / "sleep.py", tmp_path / "grandchild.pid"
    script.write_bytes(SLEEPS.encode())
    script_args(monkeypatch, pidfile)

    def age() -> None:
        while not pidfile.exists():
            threading.Event().wait(0.02)
        fixed.advance(301)

    threading.Thread(target=age, daemon=True).start()
    code = tine("run", script, "--stop-run", "r", "--stop-key",
                key_file(tmp_path, RUNNER, "runner"))  # fmt: skip
    assert code == 3
    assert dead(int(pidfile.read_text()))
    claim = _held_claim(repo)
    assert claim["code"] == "stop.continue-stale" and claim["residual_processes"] == 0


@linux
def test_every_parallel_member_is_covered(tmp_path, monkeypatch, fixed):
    channel, (repo, other) = _policy_repo(tmp_path, monkeypatch, fixed, 2)
    script = tmp_path / "member.py"
    script.write_bytes((STOPS.replace(
        "grandchild(pidfile)\n",
        "pidfile = pidfile + os.environ['OPENTINE_FANOUT_INDEX']\ngrandchild(pidfile)\n"
        "import glob\nif pidfile.endswith('1'):\n"
        "    while len(glob.glob(pidfile[:-1] + '?')) < 2: time.sleep(0.05)\n"
        "else:\n    time.sleep(3600)\n", 1)).encode())  # fmt: skip
    pidfile = tmp_path / "gc"
    script_args(monkeypatch, Path(other.path).parent, channel, STOPPER, pidfile, fixed())
    code = tine("run", script, "--parallel", "2", "--env", "PYTHONPATH", "--env",
                "TINE_TEST_ARGS", "--stop-run", "r", "--stop-key",
                key_file(tmp_path, RUNNER, "runner"))  # fmt: skip
    assert code == 3
    pids = [int((tmp_path / f"gc{i}").read_text()) for i in range(2)]
    assert all(dead(pid) for pid in pids)
    # the parent signs; a member (a supervised run of its own) signs too if it gets there
    # before the parent's tree kill reaches it
    claims = [repo.get(r).payload()["claim"] for r in _stop_compliance.held(repo)]
    assert 1 <= len(claims) <= 3 and all(c["residual_processes"] == 0 for c in claims)
    assert {c["code"] for c in claims} == {"stop.stopped"}


@linux
def test_a_child_forged_record_never_replaces_the_parents(tmp_path, monkeypatch, fixed):
    """A child that exits 3 holding a forged "compliant" record: the parent still measures
    and signs its own, which counts the setsid grandchild the child left alive."""
    channel, repos = fleet(tmp_path, 2, watchdog_s=30)  # no watchdog tick: only the exit
    repo, other = repos
    keep_going(repo, channel, ["r"], fixed)
    monkeypatch.chdir(Path(repo.path).parent)
    script, pidfile = tmp_path / "forge.py", tmp_path / "grandchild.pid"
    script.write_bytes(FORGES.encode())
    key = key_file(tmp_path, RUNNER, "runner")
    script_args(monkeypatch, Path(other.path).parent, channel, STOPPER, pidfile, fixed(), key)
    assert tine("run", script, "--stop-run", "r", "--stop-key", key) == 3
    assert dead(int(pidfile.read_text()))  # counted, then still killed
    claims = [repo.get(r).payload()["claim"] for r in _stop_compliance.held(repo)]
    assert [c["residual_method"] for c in claims].count("in-process") == 1  # the forgery
    (parent,) = [c for c in claims if c["residual_method"] != "in-process"]
    assert parent["residual_processes"] > 0 and parent["compliant"] is False


class _Calls:
    def __init__(self) -> None:
        self.argv: list[list[str]] = []

    def install(self, monkeypatch) -> None:
        def run(supervised, argv, env, *, interval_s):
            self.argv.append(argv)
            assert env[_stop_tree.SUPERVISED_ENV] == "fleet-a:r" and interval_s == 1
            return 0

        monkeypatch.setattr(_stop_supervise.Supervised, "run", run)


@pytest.mark.parametrize("mode", [["--harness", "claude-code", "--prompt", "x"], ["s.py"],
                                  ["s.py", "--parallel", "2"],
                                  ["--model", "mock", "--prompt", "p"]])  # fmt: skip
def test_every_run_mode_is_supervised(tmp_path, monkeypatch, fixed, mode):
    _policy_repo(tmp_path, monkeypatch, fixed)
    calls = _Calls()
    calls.install(monkeypatch)
    argv = ["run", *mode, "--stop-run", "r", "--stop-key", key_file(tmp_path, RUNNER, "k")]
    assert tine(*argv) == 0
    (child,) = calls.argv
    assert child[1:4] == ["-P", "-m", "opentine.cli"] and child[4:] == [str(a) for a in argv]


def test_without_a_policy_nothing_is_supervised(tmp_path, monkeypatch):
    make_repo(tmp_path / "plain")
    monkeypatch.chdir(tmp_path / "plain")
    calls = _Calls()
    calls.install(monkeypatch)
    (tmp_path / "plain" / "s.py").write_bytes(b"x = 1\n")
    assert tine("run", "s.py") == 1  # unchanged: the script has no Run object
    assert calls.argv == []


def test_a_failed_child_is_rechecked_and_a_halt_recorded(tmp_path, monkeypatch, fixed):
    """The child's own watchdog killed it: the parent's final check records the halt."""
    channel, (repo,) = _policy_repo(tmp_path, monkeypatch, fixed)
    monkeypatch.setattr(_stop_supervise.Supervised, "run", lambda *a, **k: fixed.advance(301)
                        and -9)  # fmt: skip
    assert tine("run", "s.py", "--stop-run", "r", "--stop-key",
                key_file(tmp_path, RUNNER, "k")) == 3  # fmt: skip
    assert _held_claim(repo)["code"] == "stop.continue-stale"


def test_a_forged_marker_keeps_the_start_check_and_a_watchdog(tmp_path, monkeypatch, fixed):
    """Outside a supervisor the marker skips nothing a run could use to keep going."""
    channel, (repo,) = _policy_repo(tmp_path, monkeypatch, fixed)
    monkeypatch.setenv(_stop_tree.SUPERVISED_ENV, "fleet-a:r")
    fired = []
    monkeypatch.setattr(_stop_tree, "_halt_self", fired.append)
    started = []
    real = _stop_guard.Watchdog.start
    monkeypatch.setattr(_stop_guard.Watchdog, "start",
                        lambda self: started.append(self) or real(self))  # fmt: skip
    fixed.advance(301)
    assert tine("run", "s.py", "--stop-run", "r", "--stop-key",
                key_file(tmp_path, RUNNER, "k")) == 3  # stale: refused at start  # fmt: skip
    keep_going(repo, channel, ["r"], fixed)
    (Path(repo.path).parent / "s.py").write_bytes(b"x = 1\n")
    tine("run", "s.py", "--stop-run", "r", "--stop-key", key_file(tmp_path, RUNNER, "k"))
    (watchdog,) = started
    watchdog.stop()
    fixed.advance(301)
    assert watchdog.tick() is True and fired and fired[0].code == "stop.continue-stale"
