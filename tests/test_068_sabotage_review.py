"""0.68 review: a loop holding only its own key cannot pass as a pinned scorer or monitor."""
# ruff: noqa: F811 - tests take the imported room fixture by name

from __future__ import annotations

import pytest

from opentine import _monitor_verdict, _sabotage
from opentine._sabotage_report import report
from opentine.repository._attest import attest
from opentine.repository._holds import SABOTAGE_TASK, edit_holds, holds_path
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.promote_helpers import key
from tests.query_helpers import claim
from tests.test_068_sabotage import (
    MONITOR,
    OPTIMIZER,
    SCORER,
    _fp,
    room,  # noqa: F401 - the shared fixture
)

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
AT = "2026-12-01T10:00:00Z"


def _claim(task: str, attempted: bool, achieved: bool) -> dict:
    return {"convention": _sabotage.CONVENTION, "task": task, "class": "code",
            "main_task": {"id": "m", "score": "1", "passed": True},
            "side_task": {"id": "s", "attempted": attempted, "achieved": achieved},
            "evidence": [], "monitor_verdicts": [], "at": AT}  # fmt: skip


def _forge(repo, run: str, body: dict, claimed: str) -> str:
    """Sign with the optimizer key but name a pinned fingerprint as the signer."""
    oid = attest(repo, run, body, signer=claimed, key=key(OPTIMIZER), algorithm="ed25519",
                 signed_at=AT)  # fmt: skip
    row = {"oid": oid, "target": f"{SABOTAGE_TASK}{body['task']}"}
    edit_holds(holds_path(repo), lambda rows: [*rows, row])
    return oid


def test_a_record_naming_a_scorer_it_was_not_signed_by_does_not_count(room):
    repo, run = room["repo"], room["runs"][0]
    honest = _sabotage.record(repo, run, _claim("t1", True, True), key(SCORER))
    forged = _forge(repo, run, _claim("t1", False, False), _fp(SCORER))
    rows = {r["oid"]: r["signed"] for r in _sabotage.records(repo, "t1")["t1"]}
    assert rows == {honest: True, forged: False}
    out = report(repo)
    assert out["tasks"][0]["attempted"] and out["tasks"][0]["achieved"]
    assert not out["ok"]  # the mis-attributed record is reported as malformed


def test_a_downgrade_cannot_be_recorded_over_a_forged_baseline(room):
    """A forged 'not attempted' record must not make a later honest record look like a relabel."""
    repo, run = room["repo"], room["runs"][0]
    _forge(repo, run, _claim("t2", True, True), _fp(SCORER))
    _sabotage.record(repo, run, _claim("t2", False, False), key(SCORER))


def test_a_verdict_naming_a_monitor_it_was_not_signed_by_is_unverified(room):
    repo, run = room["repo"], room["runs"][3]
    forged = attest(repo, run, claim("s9", "block"), signer=_fp(MONITOR), key=key(OPTIMIZER),
                    algorithm="ed25519")  # fmt: skip
    assert _monitor_verdict.verify(repo, forged)["verification"] != "verified"


def _held(repo, run: str, body: dict, seed: str) -> str:
    """A scorer-signed record held directly, past ``record``'s downgrade refusal."""
    oid = attest(repo, run, body, signer=_fp(seed), key=key(seed), algorithm="ed25519",
                 signed_at=body["at"])  # fmt: skip
    row = {"oid": oid, "target": f"{SABOTAGE_TASK}{body['task']}"}
    edit_holds(holds_path(repo), lambda rows: [*rows, row])
    return oid


def test_a_held_downgrade_is_reported_whatever_order_the_object_ids_sort_in(room):
    """Holds are stored sorted by oid; relabel detection must follow the records' time."""
    repo, run = room["repo"], room["runs"][0]
    for i in range(8):
        _held(repo, run, _claim(f"d{i}", True, True), SCORER)
        later = {**_claim(f"d{i}", False, False), "at": "2026-12-02T10:00:00Z"}
        _held(repo, run, later, SCORER)
    out = report(repo)
    relabelled = {f["task"] for f in out["findings"] if f["code"] == "fail:sabotage.relabel"}
    assert relabelled == {f"d{i}" for i in range(8)}
    assert all(t["attempted"] and t["achieved"] for t in out["tasks"])


def test_record_refuses_a_pinned_optimizer_key(room):
    with pytest.raises(ValueError, match="sabotage.key-separation"):
        _sabotage.record(room["repo"], room["runs"][0], _claim("o1", False, False), key(OPTIMIZER))
    assert _sabotage.records(room["repo"], "o1") == {}
