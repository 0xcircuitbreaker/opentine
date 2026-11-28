"""0.91 acceptance, end to end: a tripwire trip stops the fleet; custody copies need a quorum.

One repository under a stop policy: a run continues on a fresh proof, a decoy
touch trips a ``stop`` tripwire, the trip is held and routed to the oversight
queue and publishes a fleet stop to the channel, and the run then halts with
``stop.stopped``. Optimizer keys can neither edit the registry nor stop the
fleet, and a repository without a stop policy is unchanged (D12). Custody: a
copy is refused short of two distinct custodian approvals. Every clock is
injected; nothing reads the wall.
"""

from __future__ import annotations

import pytest

from opentine import _oversight_queue, _stop_channel, _stop_ops, _stop_policy
from opentine import _tripwire_check as tc
from opentine import _tripwire_registry as reg
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.monitor_ledger_helpers import T0, event, ingest, key, repo_fixture, tine  # noqa: F401
from tests.tripwire_helpers import digest, wire

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
DECOY = "/home/agent/.ssh/id_backup"
FLEET = "fleet-e2e"


def _stop_policy_on(repo, tmp_path):
    channel = tmp_path / "channel"
    vkey = _stop_channel.init(channel, FLEET)
    _stop_policy.install(repo, _stop_policy.make(FLEET, channel.as_posix(), vkey))
    return channel, _stop_policy.load(repo)


def test_a_decoy_trip_stops_the_fleet_and_reaches_the_queue(repo, tmp_path, capsys):
    channel, policy = _stop_policy_on(repo, tmp_path)
    _stop_ops.issue_continue(repo, channel, FLEET, ["r1"], key("policy"), window_s=300,
                             now_ms=T0)  # fmt: skip
    assert _stop_ops.status(repo, policy, "r1", T0 + 1)["ok"]
    with pytest.raises(reg.TripwireError):  # an optimizer key cannot edit the registry
        reg.write(repo, [wire("x")], key("optimizer"), now=T0 / 1000)
    with pytest.raises(ValueError):  # nor stop the fleet
        _stop_ops.issue_stop(repo, channel, FLEET, key("optimizer"), reason="x", now_ms=T0)
    reg.write(repo, [wire("decoy", metric="decoy.touches", action="stop",
                          decoys=[digest(DECOY)])], key("policy"), now=T0 / 1000)  # fmt: skip
    ingest(repo, [event(f"cp {DECOY} /tmp/x")], T0 + 2)
    code, body = tine(capsys, "tripwire", "check", "--key", "policy.key", "--now-ms",
                      str(T0 + 3), "--repo", "r", "--json")  # fmt: skip
    assert code == 1
    [trip] = body["recorded"]
    assert trip["action"] == "stop" and trip["fleet_stop"]["error"] is None
    stopped = _stop_ops.status(repo, policy, "r1", T0 + 4)
    assert not stopped["ok"] and stopped["code"] == "stop.stopped"
    assert stopped["stops"] == [trip["fleet_stop"]["attestation"]]
    sources = [i["item"] for i in _oversight_queue._sources(repo) if i["source"] == "tripwire"]
    assert sources == [f"tripwire:{trip['record']}"]
    # a new continue proof cannot un-stop the fleet
    with pytest.raises(ValueError):
        _stop_ops.issue_continue(repo, channel, FLEET, ["r1"], key("policy"), window_s=300,
                                 now_ms=T0 + 5)  # fmt: skip
    # the trip is recorded once per tripwire and registry version
    assert tc.record(repo, tc.evaluate(repo, now_ms=T0 + 6), key("policy"), now=T0 / 1000) == []


def test_without_a_stop_policy_a_stop_trip_writes_no_fleet_stop(repo, capsys):
    reg.write(repo, [wire("decoy", metric="decoy.touches", action="stop",
                          decoys=[digest(DECOY)])], key("policy"), now=T0 / 1000)  # fmt: skip
    ingest(repo, [event(f"cat {DECOY}")], T0 + 1)
    code, body = tine(capsys, "tripwire", "check", "--key", "policy.key", "--now-ms",
                      str(T0 + 2), "--repo", "r", "--json")  # fmt: skip
    assert code == 1 and body["recorded"][0]["fleet_stop"] is None


def test_an_unreachable_channel_is_reported_and_the_run_still_halts(repo, tmp_path, capsys):
    import shutil

    channel, policy = _stop_policy_on(repo, tmp_path)
    reg.write(repo, [wire("decoy", metric="decoy.touches", action="stop",
                          decoys=[digest(DECOY)])], key("policy"), now=T0 / 1000)  # fmt: skip
    ingest(repo, [event(f"cat {DECOY}")], T0 + 1)
    shutil.rmtree(channel)
    code, body = tine(capsys, "tripwire", "check", "--key", "policy.key", "--now-ms",
                      str(T0 + 2), "--repo", "r", "--json")  # fmt: skip
    assert code == 1 and body["recorded"][0]["fleet_stop"]["error"]
    assert body["recorded"][0]["stop"]  # the local stop token is still written
    assert _stop_ops.status(repo, policy, "r1", T0 + 3)["code"] == "stop.channel-unreachable"


def test_a_custody_copy_needs_two_distinct_custodians(tmp_path, monkeypatch):
    from opentine import _custody_quorum as quorum
    from tests import test_091_custody_quorum as cq

    store = cq.repo.__wrapped__(tmp_path, monkeypatch)
    with pytest.raises(quorum.QuorumError):
        cq._copy(store)
    cq._approve(store, "c1")
    cq._approve(store, "c1")
    with pytest.raises(quorum.QuorumError):
        cq._copy(store)
    cq._approve(store, "c2")
    assert cq._copy(store)["seq"] == 1
    assert cq.check.check(store, "m")["ok"]
