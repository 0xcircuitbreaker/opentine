"""0.91: tripwires over ingest, monitor, suspicion and budget signals; trips stop.

A decoy touch stops the loop through the existing stop token; suspicion and
monitor outcomes from the 0.90 coverage ledgers trip a flag that is held and
routed to the oversight queue; a signal that cannot be read trips (fail
closed); a forged trip neither counts nor suppresses a real one. Clocks are
injected (``now_ms``), never read.
"""

from __future__ import annotations

import pytest

from opentine import _containment_records as records
from opentine import _monitor_stop, _oversight_queue
from opentine import _tripwire_check as tc
from opentine import _tripwire_registry as reg
from opentine import _tripwire_signals as signals
from opentine._monitor_runner import Runner
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.monitor_ledger_helpers import (  # noqa: F401
    T0,
    config,
    event,
    ingest,
    key,
    repo_fixture,
    tine,
)
from tests.tripwire_helpers import digest, wire

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
DECOY = "/home/agent/.aws/credentials-backup"


def _register(repo, *wires: dict) -> str:
    return reg.write(repo, list(wires), key("policy"), now=T0 / 1000)["record"]


def _check(repo, name: str = "monitor", at: int = T0) -> tuple[dict, list]:
    result = tc.evaluate(repo, now_ms=at)
    return result, tc.record(repo, result, key(name), now=at / 1000)


def test_a_decoy_touch_stops_the_loop(repo, capsys):
    _register(repo, wire("decoy", metric="decoy.touches", scope="stream:rl", action="stop",
                         decoys=[digest(DECOY)]))  # fmt: skip
    ingest(repo, [event("ls /tmp")], T0)
    code, body = tine(capsys, "tripwire", "check", "--key", "monitor.key", "--now-ms", str(T0),
                      "--repo", "r", "--json")  # fmt: skip
    assert code == 0 and body["recorded"] == [] and _monitor_stop.active(repo, ["*"]) is None
    ingest(repo, [event(f"cat {DECOY} | base64")], T0 + 1)
    code, body = tine(capsys, "tripwire", "check", "--key", "monitor.key", "--now-ms",
                      str(T0 + 2), "--repo", "r", "--json")  # fmt: skip
    assert code == 1
    [row] = body["tripwires"]
    assert row["tripped"] and row["value"] == 1.0 and len(row["evidence"]) == 1
    [trip] = body["recorded"]
    assert trip["action"] == "stop" and _monitor_stop.active(repo, ["*"])["token"] == trip["stop"]
    claim = records.read(repo, trip["record"])["claim"]
    assert claim["tripwire"]["decoys"] == [digest(DECOY)] and claim["stop"] == trip["stop"]
    code, listed = tine(capsys, "tripwire", "trips", "--repo", "r", "--json")
    assert code == 0 and [t["counted"] for t in listed["trips"]] == [True]


def test_the_registry_never_holds_the_decoy_itself(repo):
    head = _register(repo, wire("decoy", metric="decoy.touches", decoys=[digest(DECOY)]))
    assert DECOY.encode() not in repr(records.read(repo, head)["claim"]).encode()
    assert digest(DECOY) in signals.digests({"arguments": {"cmd": f"tar czf x.tgz {DECOY}"}})


def test_suspicion_trips_a_flag_that_reaches_the_oversight_queue(repo):
    _register(
        repo,
        wire("probing", metric="suspicion.flags", scope="agent:a1"),
        wire("nonallow", metric="monitor.non-allow", scope="stream:rl", threshold=2),
    )
    for n in range(3):
        ingest(repo, [event(f"probe {n}", session=f"s{n}")], T0 + n)
    Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0 + 10).once()
    result, written = _check(repo, at=T0 + 20)
    rows = {r["id"]: r for r in result["tripwires"]}
    assert rows["probing"]["tripped"] and rows["probing"]["evidence"]
    assert not rows["nonallow"]["tripped"]  # probes score under the threshold: allow
    assert [(w["tripwire"], w["action"], w["stop"]) for w in written] == [
        ("probing", "flag", None)]  # fmt: skip
    items = {i["item"]: i["source"] for i in _oversight_queue._sources(repo)}
    assert items[f"tripwire:{written[0]['record']}"] == "tripwire"
    assert _monitor_stop.active(repo, ["*", "agent:a1"]) is None  # a flag does not stop


def test_monitor_outcomes_trip_on_the_agent_scope_with_an_agent_stop(repo):
    _register(repo, wire("destructive", metric="monitor.non-allow", scope="agent:a2",
                         action="stop"))  # fmt: skip
    ingest(repo, [event("rm -rf /", agent="a2"), event("rm -rf ~", agent="a1")], T0)
    Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0 + 10).once()
    result, written = _check(repo, at=T0 + 20)
    assert result["tripwires"][0]["value"] == 1.0
    assert _monitor_stop.active(repo, ["agent:a2"])["token"] == written[0]["stop"]
    assert _monitor_stop.active(repo, ["*"]) is None


def test_a_trip_is_recorded_once_per_registry_version(repo):
    _register(repo, wire("busy", metric="ingest.events", threshold=1))
    ingest(repo, [event("ls")], T0)
    assert len(_check(repo)[1]) == 1
    assert _check(repo, at=T0 + 1)[1] == []
    _register(repo, wire("busy", metric="ingest.events", threshold=1), wire("other"))
    assert [w["tripwire"] for w in _check(repo, at=T0 + 2)[1]] == ["busy"]


def test_a_forged_trip_neither_counts_nor_suppresses_a_real_one(repo):
    head = _register(repo, wire("busy", metric="ingest.events", threshold=1))
    forged = {"convention": tc.CONVENTION, "tripwire": wire("busy"), "registry": head,
              "serial": 1, "value": 0.0, "evidence": [], "action": "flag", "stop": None,
              "reason": "already handled", "at": "2027-01-15T08:00:00Z"}  # fmt: skip
    records.record(repo, records.anchor(repo, "forge", "x"), forged, key("optimizer"),
                   tc.HOLD + "busy")  # fmt: skip
    ingest(repo, [event("ls")], T0)
    _, written = _check(repo)
    assert [w["tripwire"] for w in written] == ["busy"]
    assert sorted(t["counted"] for t in tc.trips(repo)) == [False, True]


def test_a_signal_that_cannot_be_read_trips(repo, monkeypatch):
    _register(repo, wire("w1"))

    def broken(*_a, **_k):
        raise OSError("ledger unreadable")

    monkeypatch.setattr(signals, "value", broken)
    result = tc.evaluate(repo, now_ms=T0)
    assert result["tripwires"][0]["tripped"] and "unreadable" in result["tripwires"][0]["error"]
    assert not result["ok"]


def test_a_budget_signal_reads_the_ledger_at_the_injected_time(repo):
    _register(repo, wire("idle", metric="budget.tokens", scope="budget:agent:a1", op="<=",
                         threshold=0))  # fmt: skip
    result = tc.evaluate(repo, now_ms=T0)
    assert result["tripwires"][0]["value"] == 0.0 and result["tripwires"][0]["tripped"]


def test_check_without_a_key_reports_only(repo, capsys):
    _register(repo, wire("busy", metric="ingest.events", threshold=1))
    ingest(repo, [event("ls")], T0)
    code, body = tine(capsys, "tripwire", "check", "--now-ms", str(T0), "--repo", "r", "--json")
    assert code == 1 and body["recorded"] == [] and tc.trips(repo) == []
