"""Hostile-loop review of monitors as evidence: each test is one hole that was open."""

from __future__ import annotations

import pytest

from opentine import (
    _ingest_holds,
    _monitor_coverage,
    _monitor_heartbeat,
    _monitor_ledger,
    _monitor_suspicion,
)
from opentine._monitor_runner import Runner
from opentine._monitor_verdict import monitors
from opentine.repository._holds import MONITOR_LEDGER
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.monitor_ledger_helpers import (  # noqa: F401
    CONFIG,
    T0,
    config,
    event,
    ingest,
    key,
    repo_fixture,
)

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
MIN = 60_000


def _beats(repo, now_ms: int) -> dict:
    ident = _monitor_ledger.identity(config())
    batches, _ = _monitor_ledger.walk(repo, _ingest_holds.head(repo, "rl"),
                                      "opentine.ingest-batch/1")  # fmt: skip
    return _monitor_heartbeat.check(repo, ident, "rl", batches, now_ms=now_ms,
                                    keys=monitors(repo)[0], gating=False)  # fmt: skip


def _codes(body: dict) -> set[str]:
    return {f["code"] for f in body["findings"]}


def _report(repo, **kw):
    cfg = config()
    return _monitor_coverage.report(repo, "rl", _monitor_ledger.identity(cfg), now_ms=T0 + 2_000,
                                    threshold=cfg["threshold"], **kw)  # fmt: skip


def test_a_future_dated_heartbeat_does_not_keep_a_dead_monitor_alive(repo):
    Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0 + 1_000 * MIN).heartbeat()
    body = _beats(repo, T0 + 5 * MIN)
    assert "fail:monitor.heartbeat-future" in _codes(body)
    assert "advisory:monitor.stale" in _codes(body)


def test_a_heartbeat_of_another_config_is_no_liveness_for_this_one(repo):
    other = config(CONFIG.replace("threshold = 0.5", "threshold = 0.9"))
    Runner(repo, other, "rl", key("monitor"), clock_ms=lambda: T0).heartbeat()
    body = _beats(repo, T0 + 1)
    assert "advisory:monitor.config-changed" in _codes(body)
    assert "advisory:monitor.stale" in _codes(body)


def test_a_monitor_that_errors_on_every_event_covers_nothing(repo):
    ingest(repo, [event("rm -rf /"), event("ls")], T0)
    stalled = Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0 + 1_000,
                     runner=lambda fn, s: (False, None, None))  # fmt: skip
    stalled.once()
    body = _report(repo)
    assert body["covered"] == "0/2" and body["gaps"] == [[0, 1]]


def _forge(repo, rows_edit, ident=None) -> None:
    ingest(repo, [event("rm -rf /"), event("ls")], T0)
    batch = _ingest_holds.read(repo, _ingest_holds.head(repo, "rl"), "opentine.ingest-batch/1")
    ident = ident or _monitor_ledger.identity(config())
    rows = rows_edit(
        [
            {"i": 0, "s": 0.0, "a": "allow", "d": "sha256:" + "0" * 64, "l": 1},
            {"i": 1, "s": 0.0, "a": "allow", "d": "sha256:" + "1" * 64, "l": 1},
        ]
    )
    row = _monitor_ledger.append(
        repo,
        ident,
        "rl",
        {"id": batch["id"], **batch["claim"]},
        rows,
        key("monitor"),
        threshold=0.5,
        at="2027-01-15T08:20:00Z",
    )
    if ident["id"] != "rules":
        _ingest_holds.move_head(repo, "rules@rl", None, row["id"], prefix=MONITOR_LEDGER)


def test_coverage_for_events_the_monitor_never_saw_is_forged(repo):
    _forge(repo, lambda rows: rows)  # digests of other inputs: it scored something else
    body = _report(repo)
    assert "fail:monitor.coverage-forged" in _codes(body) and body["covered"] == "0/2"


def test_another_monitors_ledger_cannot_stand_in(repo):
    from opentine._monitor_runner import _events, _request
    from opentine._monitor_verdict import digest

    def honest(rows):
        batch = _ingest_holds.read(repo, _ingest_holds.head(repo, "rl"), "opentine.ingest-batch/1")
        lines = _events(batch["claim"])
        for row, line in zip(rows, lines, strict=True):
            row["d"] = digest(_request(str(line.get("k", "event")), line.get("e")))
        return rows

    ident = {**_monitor_ledger.identity(config()), "id": "other"}
    _forge(repo, honest, ident)
    body = _report(repo)
    assert "fail:monitor.coverage-forged" in _codes(body) and body["covered"] == "0/2"


def test_rotating_every_self_claimed_identity_still_escalates_on_the_stream(repo):
    for n in range(3):
        ingest(repo, [event(f"probe {n}", agent=f"a{n}", session=f"s{n}", run=f"r{n}")], T0 + n)
    Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0 + 1_000).once()
    body = _monitor_suspicion.scan(repo, _monitor_ledger.chains(repo), monitors(repo)[0])
    flags = {(f["code"].split(".", 1)[1], f["subject"]) for f in body["flags"]}
    assert ("doom-loop-near-threshold", "stream:rl") in flags
