"""0.91 review: hostile attempts on tripwire signals and custody quorum dating."""

from __future__ import annotations

import pytest

from opentine import _containment_records as records
from opentine import _custody_quorum as quorum
from opentine import _monitor_stop
from opentine import _tripwire_check as tc
from opentine import _tripwire_registry as reg
from opentine import _weight_custody as wc
from opentine import _weight_custody_check as check
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.monitor_ledger_helpers import (  # noqa: F401
    T0,
    config,
    event,
    ingest,
    key,
    repo_fixture,
)
from tests.test_091_custody_quorum import AT, W1, _approve
from tests.test_091_custody_quorum import key as ckey
from tests.test_091_custody_quorum import repo as custody_repo  # noqa: F401
from tests.tripwire_helpers import digest, wire

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
DECOY = "/srv/decoy/token-backup"


def test_deleting_a_batch_that_touched_a_decoy_trips_instead_of_blinding(repo):
    reg.write(repo, [wire("decoy", metric="decoy.touches", scope="stream:rl", action="stop",
                          decoys=[digest(DECOY)])], key("policy"), now=T0 / 1000)  # fmt: skip
    touched = ingest(repo, [event(f"cat {DECOY}")], T0)["id"]
    ingest(repo, [event("ls")], T0 + 1)
    repo._object_path(touched).unlink()  # the loop deletes the evidence
    result = tc.evaluate(repo, now_ms=T0 + 2)
    [row] = result["tripwires"]
    assert row["tripped"] and row["error"] and not result["ok"]


def test_a_backdated_copy_does_not_escape_a_revocation(custody_repo):  # noqa: F811
    repo = custody_repo
    first = _approve(repo, "c1")
    _approve(repo, "c2")
    quorum.revoke(repo, first, ckey("c1"), now=AT + 100)
    rows = wc.events(repo, "m")
    claim = {"convention": wc.CONVENTION, "artifact": "m", "event": "copied", "seq": 1,
             "prev": rows[0]["oid"], "location": "s3://x/m", "digest": W1, "size": None,
             "run": None, "data": [], "lineage": None, "tags": [],
             "recorded_at": "2027-01-15T08:00:05Z"}  # fmt: skip
    records.record(repo, rows[0]["target"], claim, ckey("runner"), f"{wc.HOLD}m:{1:08d}")
    body = check.check(repo, "m")
    assert check.COPY_UNAPPROVED in {f["code"] for f in body["findings"]}


def test_deleting_the_newest_registry_version_does_not_roll_the_registry_back(repo):
    reg.write(repo, [wire("a")], key("policy"), now=T0 / 1000)
    newest = reg.write(repo, [wire("a"), wire("b", action="stop")], key("policy"),
                       now=T0 / 1000 + 1)["record"]  # fmt: skip
    repo._object_path(newest).unlink()  # drops tripwire b
    state = reg.current(repo)
    assert state["status"] == "broken" and state["tripwires"] == []


def test_deleting_the_newest_version_trips_even_without_a_pinned_rule(repo):
    reg.write(repo, [wire("a", action="stop")], key("policy"), now=T0 / 1000)
    newest = reg.write(repo, [wire("a", action="stop"), wire("b")], key("policy"),
                       now=T0 / 1000 + 1)["record"]  # fmt: skip
    repo._object_path(newest).unlink()
    result = tc.evaluate(repo, now_ms=T0)
    assert not result["ok"] and result["missing"]
    [trip] = tc.record(repo, result, key("monitor"), now=T0 / 1000)
    assert trip["action"] == "stop" and _monitor_stop.active(repo, ["*"])["token"] == trip["stop"]
