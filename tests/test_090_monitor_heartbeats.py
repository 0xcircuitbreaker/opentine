"""Signed monitor heartbeats: stale detection, no backfill, no replay, the follow loop."""

from __future__ import annotations

import threading

import pytest

from opentine import _ingest_holds, _monitor_heartbeat, _monitor_ledger
from opentine._monitor_runner import Runner
from opentine._monitor_verdict import monitors
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.monitor_ledger_helpers import T0, config, event, ingest, key, repo_fixture  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
MIN = 60_000


class Clock:
    def __init__(self, start: int) -> None:
        self.now = start

    def __call__(self) -> int:
        return self.now


def _check(repo, now_ms: int, gating: bool = False) -> dict:
    ident = _monitor_ledger.identity(config())
    batches, _ = _monitor_ledger.walk(repo, _ingest_holds.head(repo, "rl"),
                                      "opentine.ingest-batch/1")  # fmt: skip
    return _monitor_heartbeat.check(repo, ident, "rl", batches, now_ms=now_ms,
                                    keys=monitors(repo)[0], gating=gating)  # fmt: skip


def _codes(body: dict) -> set[str]:
    return {f["code"] for f in body["findings"]}


def test_a_live_follow_loop_beats_once_per_interval_and_is_not_stale(repo):
    clock = Clock(T0)
    runner = Runner(repo, config(), "rl", key("monitor"), clock_ms=clock)
    stop, rounds = threading.Event(), []

    def wait(_seconds: float) -> None:  # one poll is 20 s of injected time
        rounds.append(clock.now)
        clock.now += 20_000
        if len(rounds) == 1:
            ingest(repo, [event("ls")], clock.now - 1)
        if len(rounds) == 12:
            stop.set()

    counts = runner.follow(stop, wait=wait)
    assert counts["heartbeats"] == 4 and counts["batches"] == 1
    body = _check(repo, clock.now)
    assert body["heartbeats"] == 4 and body["stale_windows"] == [] and not body["findings"]


def test_a_killed_monitor_goes_stale_after_three_missed_intervals(repo):
    clock = Clock(T0)
    runner = Runner(repo, config(), "rl", key("monitor"), clock_ms=clock)
    runner.heartbeat()
    clock.now += MIN
    runner.heartbeat()  # then the process is killed: no more heartbeats
    assert _check(repo, clock.now + 3 * MIN)["stale_windows"] == []
    body = _check(repo, clock.now + 3 * MIN + 1)
    assert body["stale_windows"] == [{"from": T0 + MIN, "to": T0 + 4 * MIN + 1}]
    assert "advisory:monitor.stale" in _codes(body)
    assert "fail:monitor.stale" in _codes(_check(repo, clock.now + 4 * MIN, gating=True))


def test_no_heartbeat_at_all_is_stale(repo):
    assert "advisory:monitor.stale" in _codes(_check(repo, T0))


def test_a_restarted_monitor_cannot_backfill_the_gap(repo):
    clock = Clock(T0)
    runner = Runner(repo, config(), "rl", key("monitor"), clock_ms=clock)
    runner.heartbeat()
    ingest(repo, [event("ls")], T0 + 10 * MIN)  # events kept arriving while it was down
    clock.now = T0 + 2 * MIN  # the restarted process claims an earlier time
    with pytest.raises(_monitor_heartbeat.HeartbeatError):
        runner.heartbeat()


def test_a_forged_heartbeat_bound_to_an_old_head_is_backfilled(repo):
    ingest(repo, [event("ls")], T0)
    old = _ingest_holds.head(repo, "rl")
    ingest(repo, [event("ls 2")], T0 + MIN)
    ident = _monitor_ledger.identity(config())
    batch = _ingest_holds.read(repo, old, "opentine.ingest-batch/1")
    claim = {"convention": _monitor_heartbeat.CONVENTION, "monitor": ident, "stream": "rl",
             "seq": 0, "previous": None, "interval_s": 60, "ledger": None,
             "ingest": {"head": old, "seq": 0, "at": batch["claim"]["at"]},
             "at": "2027-01-15T08:20:00Z"}  # fmt: skip
    from opentine._ingest_policy import anchor
    from opentine.repository._holds import MONITOR_HEARTBEAT

    oid = _ingest_holds.write(repo, anchor(repo, "rl"), claim, key("monitor"), previous=None,
                              signed_at=claim["at"])  # fmt: skip
    _ingest_holds.move_head(repo, "rules@rl", None, oid, prefix=MONITOR_HEARTBEAT)
    body = _check(repo, T0 + 21 * MIN)  # checked after the heartbeat's own time
    assert "fail:monitor.heartbeat-backfilled" in _codes(body)


def test_a_heartbeat_replayed_from_another_monitor_is_refused(repo):
    other = config(__import__("tests.monitor_ledger_helpers", fromlist=["CONFIG"]).CONFIG
                   .replace('id = "rules"', 'id = "other"'))  # fmt: skip
    clock = Clock(T0)
    row = Runner(repo, other, "rl", key("monitor"), clock_ms=clock).heartbeat()
    from opentine.repository._holds import MONITOR_HEARTBEAT

    _ingest_holds.move_head(repo, "rules@rl", None, row["id"], prefix=MONITOR_HEARTBEAT)
    body = _check(repo, T0 + 1)
    assert "fail:monitor.heartbeat-replayed" in _codes(body)


def test_heartbeats_by_an_unpinned_key_do_not_prove_liveness(repo):
    Runner(repo, config(), "rl", key("stranger"), clock_ms=lambda: T0).heartbeat()
    body = _check(repo, T0 + 1)
    assert "fail:monitor.heartbeat-unsigned" in _codes(body)
    assert "advisory:monitor.stale" in _codes(body)
