"""0.91 review: stop-compliance measurement and freshness a hostile loop cannot bend.

Each test is one hole found in review. Clocks are injected; nothing waits on time.
"""

from __future__ import annotations

from pathlib import Path

from opentine import _stop_compliance, _stop_policy
from opentine._stop_guard import Halt, StopGuard, anchored_clock
from opentine._stop_runner import StopRunner
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401 - autouse
from tests.stop_helpers import RUNNER, Clock, fleet, halt_fleet, keep_going, key


def _runner(tmp_path: Path, clock: Clock) -> StopRunner:
    channel, (repo,) = fleet(tmp_path)
    keep_going(repo, channel, ["r"], clock)
    return StopRunner(repo, _stop_policy.load(repo), "r", key(RUNNER), clock_ms=clock)


def test_a_record_claiming_compliant_over_its_own_numbers_is_flagged(tmp_path):
    clock = Clock()
    stop = _runner(tmp_path, clock)
    clock.advance(301)
    stop.supervised.admit()
    claim = stop.finish()["claim"]
    forged = dict(claim, residual_processes=2, compliant=True)  # a runner-signed lie
    oid = _stop_compliance.record(stop.repo, forged, key(RUNNER))
    assert "residual" in (_stop_compliance.check(stop.repo, oid) or "")
    for field, bad in (("time_to_halt_ms", True), ("forwarded_after_stop", 1.5),
                       ("residual_processes", None)):  # fmt: skip
        oid = _stop_compliance.record(stop.repo, dict(claim, **{field: bad}), key(RUNNER))
        assert _stop_compliance.check(stop.repo, oid) is not None, field


def test_a_halt_long_after_a_fleet_stop_is_not_compliant(tmp_path):
    clock = Clock()
    stop = _runner(tmp_path, clock)
    halt_fleet(stop.repo, Path(stop.policy["channel"]), clock)
    clock.advance(200)  # inside the freshness window, but many watchdog intervals late
    assert stop.supervised.admit().code == "stop.stopped"
    assert stop.finish()["claim"]["compliant"] is False


def test_residual_processes_are_counted_before_any_second_kill(tmp_path, monkeypatch):
    import opentine._stop_supervise as sup
    import opentine.tools._process as proc

    clock = Clock()
    stop = _runner(tmp_path, clock)
    kills = []
    monkeypatch.setattr(proc, "_cleanup_owned", lambda *_: kills.append(1))
    monkeypatch.setattr(sup, "residual", lambda *_: (0 if len(kills) >= 2 else 1, "proc"))
    stop.supervised.settle = lambda: None  # no waiting: the count is all that matters

    class Gone:
        pid = 1

    stop.supervised.process = Gone()
    clock.advance(301)
    stop.supervised.admit()  # the first kill: one process of the tree survives it
    assert kills == [1]
    measured = stop.supervised.measure()
    assert measured["residual_processes"] == 1  # not hidden by killing it again first
    assert len(kills) >= 2  # and it is still cleaned up afterwards


def test_rolling_the_wall_clock_back_does_not_keep_a_proof_fresh(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path)
    keep_going(repo, channel, ["r"], clock)
    wall, mono = [clock() / 1000], [0.0]
    guard = StopGuard(_stop_policy.load(repo), Path(repo.path), "r",
                      clock_ms=anchored_clock(lambda: wall[0], lambda: mono[0]))  # fmt: skip
    guard.check()
    mono[0] += 400  # 400 s pass ...
    wall[0] -= 600  # ... while the loop sets the system clock back
    try:
        guard.check()
    except Halt as halt:
        assert halt.code == "stop.continue-stale"
    else:
        raise AssertionError("a rolled-back clock kept a stale proof fresh")


def test_a_guard_clock_never_goes_backwards(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path)
    keep_going(repo, channel, ["r"], clock)
    guard = StopGuard(_stop_policy.load(repo), Path(repo.path), "r", clock_ms=clock)
    clock.advance(301)
    seen = guard.now_ms()
    clock.advance(-200)  # an injected clock that rolls back
    assert guard.now_ms() == seen
