"""0.91: the tripwire registry is signed by a pinned policy key and cannot be edited around.

Hostile attempts: an optimizer key adding or removing a tripwire, a forged
registry version written straight into the object store, a dropped hold row,
a fork, a rollback below the pinned floor, and a deleted registry under a
pinned rule. Every clock is injected.
"""

from __future__ import annotations

import pytest

from opentine import _containment_records as records
from opentine import _monitor_stop, _trust_bundle
from opentine import _tripwire_check as tc
from opentine import _tripwire_registry as reg
from opentine.repository._holds import HoldError, edit_holds, holds_path, release
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.monitor_ledger_helpers import T0, fpr, key, repo_fixture, tine  # noqa: F401
from tests.tripwire_helpers import pin_rule, wire

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _add(repo, ident: str = "w1", **fields) -> dict:
    state = reg.current(repo)
    return reg.write(
        repo, [*state["tripwires"], wire(ident, **fields)], key("policy"), now=T0 / 1000
    )


def test_a_policy_key_signs_each_version_and_the_chain_links_them(repo, capsys):
    code, body = tine(
        capsys,
        "tripwire",
        "add",
        "w1",
        "--metric",
        "suspicion.flags",
        "--threshold",
        "1",
        "--key",
        "policy.key",
        "--repo",
        "r",
        "--json",
    )
    assert code == 0 and body["serial"] == 1
    code, second = tine(capsys, "tripwire", "add", "w2", "--metric", "ingest.events",
                        "--threshold", "5", "--action", "stop", "--key", "policy.key",
                        "--repo", "r", "--json")  # fmt: skip
    assert code == 0 and second["serial"] == 2
    state = reg.current(repo)
    assert state["status"] == "ok" and [w["id"] for w in state["tripwires"]] == ["w1", "w2"]
    assert records.read(repo, state["head"])["claim"]["previous"] == body["record"]
    code, listed = tine(capsys, "tripwire", "list", "--repo", "r", "--json")
    assert code == 0 and listed["serial"] == 2 and listed["findings"] == []


def test_an_optimizer_key_can_neither_add_nor_remove(repo, capsys):
    _add(repo)
    for argv in (("add", "w9", "--metric", "suspicion.flags", "--threshold", "1"),
                 ("remove", "w1")):  # fmt: skip
        code, body = tine(capsys, "tripwire", *argv, "--key", "optimizer.key", "--repo", "r",
                          "--json")  # fmt: skip
        assert code == 1 and "tripwire.registry-signer" in body["error"]["message"]
    assert [w["id"] for w in reg.current(repo)["tripwires"]] == ["w1"]


def test_a_forged_version_written_around_the_command_does_not_count(repo):
    head = _add(repo)["record"]
    for name in ("optimizer", "stranger"):
        claim = {"convention": reg.CONVENTION, "serial": 2, "previous": head, "tripwires": [],
                 "at": "2027-01-15T08:00:00Z"}  # fmt: skip
        records.record(
            repo, records.anchor(repo, "forge", "x"), claim, key(name), f"{reg.HOLD}{2:08d}"
        )
    state = reg.current(repo)
    assert state["status"] == "ok" and state["head"] == head
    assert [w["id"] for w in state["tripwires"]] == ["w1"]
    codes = {f["code"] for f in state["findings"]}
    assert codes == {"fail:tripwire.registry-signer"}
    assert not tc.evaluate(repo, now_ms=T0)["ok"]  # the attempt itself is a finding


def test_dropping_a_hold_row_neither_hides_nor_rolls_back_the_registry(repo):
    _add(repo)
    head = _add(repo, "w2")["record"]
    edit_holds(holds_path(repo), lambda rows: [r for r in rows if r["oid"] != head])
    state = reg.current(repo)
    assert state["head"] == head and state["serial"] == 2
    assert {f["code"] for f in state["findings"]} == {"fail:tripwire.registry-unheld"}


def test_registry_records_are_never_released(repo):
    head = _add(repo)["record"]
    with pytest.raises(HoldError, match="never released"):
        release(repo, head)


def test_a_fork_or_a_rollback_breaks_the_registry(repo):
    head = _add(repo)["record"]
    for ident in ("a", "b"):
        claim = {"convention": reg.CONVENTION, "serial": 2, "previous": head,
                 "tripwires": [wire(ident)], "at": "2027-01-15T08:00:00Z"}  # fmt: skip
        records.record(
            repo, records.anchor(repo, "forge", "x"), claim, key("policy"), f"{reg.HOLD}{2:08d}"
        )
    state = reg.current(repo)
    assert state["status"] == "broken" and state["tripwires"] == []
    assert "fail:tripwire.registry-fork" in {f["code"] for f in state["findings"]}
    with pytest.raises(reg.TripwireError, match="registry-broken"):
        _add(repo, "c")


def test_a_registry_below_the_pinned_floor_is_a_rollback(repo):
    _add(repo)
    pin_rule(repo, {"version": 1, "required": True, "min_serial": 2})
    state = reg.current(repo)
    assert state["status"] == "broken"
    assert "fail:tripwire.registry-rollback" in {f["code"] for f in state["findings"]}


def test_a_missing_registry_under_the_pinned_rule_fails_closed_with_a_stop(repo, capsys):
    pin_rule(repo, {"version": 1, "required": True})
    code, body = tine(capsys, "tripwire", "check", "--key", "monitor.key", "--now-ms", str(T0),
                      "--repo", "r", "--json")  # fmt: skip
    assert code == 1 and body["missing"] and body["registry"]["status"] == "absent"
    [trip] = body["recorded"]
    assert trip["tripwire"] == "registry" and trip["action"] == "stop"
    assert _monitor_stop.active(repo, ["*"])["token"] == trip["stop"]
    code, again = tine(capsys, "tripwire", "check", "--key", "monitor.key", "--now-ms",
                       str(T0 + 1), "--repo", "r", "--json")  # fmt: skip
    assert code == 1 and again["recorded"] == []  # one trip per registry state


def test_without_the_rule_an_empty_registry_changes_nothing(repo, capsys):
    code, body = tine(capsys, "tripwire", "check", "--key", "monitor.key", "--now-ms", str(T0),
                      "--repo", "r", "--json")  # fmt: skip
    assert code == 0 and body["ok"] and body["recorded"] == []
    assert _monitor_stop.active(repo, ["*"]) is None


def test_an_unreadable_bundle_under_a_pinned_owner_requires_the_registry(repo):
    (repo.path / "trust-bundle.note").write_bytes(b"not a bundle\n")
    found = reg.rule(repo)
    assert found["required"] and found["error"]


@pytest.mark.parametrize("section", [
    {"version": 1, "required": "yes"}, {"version": 2}, {"version": 1, "min_serial": -1},
    {"version": 1, "extra": True}])  # fmt: skip
def test_a_malformed_rule_is_refused_by_the_bundle_validator(section):
    payload = {
        "trust_bundle": 1,
        "serial": 1,
        "issued_at": "2027-01-15T08:00:00Z",
        "trust_policy": {"pin": ["sha256:" + "0" * 64]},
        "tripwires": section,
    }
    with pytest.raises(_trust_bundle.BundleError, match="tripwires is"):
        _trust_bundle.validate(payload)


@pytest.mark.parametrize("bad", [
    {"metric": "made.up"}, {"threshold": float("nan")}, {"scope": "agent:a b"},
    {"metric": "decoy.touches"}, {"decoys": ["sha256:" + "a" * 64]},
    {"metric": "budget.tokens", "scope": "stream:rl"}, {"scope": "budget:loop:x"},
    {"id": "registry"}, {"action": "delete"}])  # fmt: skip
def test_a_malformed_tripwire_is_refused(bad):
    with pytest.raises(reg.TripwireError, match="tripwire.invalid"):
        reg.wire({**wire("w1"), **bad})


def test_a_trip_is_not_signed_by_an_optimizer_key(repo):
    pin_rule(repo, {"version": 1, "required": True})
    result = tc.evaluate(repo, now_ms=T0)
    with pytest.raises(reg.TripwireError, match="tripwire.trip-signer"):
        tc.record(repo, result, key("optimizer"), now=T0 / 1000)
    assert fpr("optimizer") not in tc.signers(repo)[0]
