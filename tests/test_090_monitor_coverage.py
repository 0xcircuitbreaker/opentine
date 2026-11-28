"""Monitor coverage ledger: exact coverage, gaps, forged records, config changes."""

from __future__ import annotations

import pytest

from opentine import _ingest_holds, _monitor_coverage, _monitor_ledger, _monitor_verdict
from opentine._monitor_runner import Runner
from opentine.repository._holds import HoldError, release
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.monitor_ledger_helpers import T0, config, event, ingest, key, repo_fixture  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _runner(repo, cfg=None, name="monitor", at=T0 + 1_000):
    return Runner(repo, cfg or config(), "rl", key(name), clock_ms=lambda: at)


def _codes(body: dict, level: str = "fail") -> set[str]:
    return {f["code"] for f in body["findings"] if f["level"] == level}


def _report(repo, cfg=None, **kw):
    cfg = cfg or config()
    return _monitor_coverage.report(repo, "rl", _monitor_ledger.identity(cfg),
                                    now_ms=kw.pop("now_ms", T0 + 2_000),
                                    threshold=cfg["threshold"], **kw)  # fmt: skip


def test_coverage_is_exact_over_ten_thousand_actions(repo):
    for b in range(4):
        ingest(repo, [event(f"ls {b}-{i}") for i in range(2_500)], T0 + b)
    runner = _runner(repo)
    rows = runner.once()
    assert [r["batch_seq"] for r in rows] == [0, 1, 2, 3]
    assert runner.counts["evaluated"] == 10_000 and runner.counts["verdicts"] == 0
    body = _report(repo)
    assert body["captured"] == 10_000 and body["covered"] == "10000/10000"
    assert body["percent"] == "100.0000" and body["gaps"] == []
    assert rows[0]["by_action"]["allow"] == 2_500  # allow is counted, never signed one by one


def test_a_batch_the_monitor_never_saw_is_a_gap_of_exactly_its_events(repo):
    ingest(repo, [event(f"ls {i}") for i in range(7)], T0)
    _runner(repo).once()
    ingest(repo, [event(f"ls {i}") for i in range(3)], T0 + 5)
    body = _report(repo)
    assert body["covered"] == "7/10" and body["percent"] == "70.0000"
    assert body["gaps"] == [[7, 9]]
    assert "advisory:monitor.coverage-gap" in _codes(body, "advisory")
    assert "fail:monitor.coverage-gap" in _codes(_report(repo, profile="rsi"))


def test_category_and_severity_reach_the_signed_verdict(repo):
    ingest(repo, [event("rm -rf /"), event("ls")], T0)
    rows = _runner(repo).once()
    assert rows[0]["by_action"]["block"] == 1 and rows[0]["by_category"] == {"destructive": 1}
    held = _monitor_verdict.held(repo)
    assert len(held) == 1
    claim = repo.get(held[0]).payload()["claim"]
    assert claim["category"] == "destructive" and claim["severity"] == "high"
    assert _monitor_verdict.check_claim(claim) == []
    assert _monitor_verdict.check_claim({**claim, "severity": "dire"})


def test_records_by_an_unpinned_or_optimizer_key_never_count(repo):
    ingest(repo, [event("ls")], T0)
    _runner(repo, name="stranger").once()
    body = _report(repo)
    assert "fail:monitor.coverage-unsigned" in _codes(body)
    assert body["evaluated"] == 0
    with pytest.raises(_monitor_ledger.LedgerError):
        _runner(repo, name="optimizer")


def test_a_hostile_ledger_claiming_uncaptured_indices_is_forged(repo):
    ingest(repo, [event("ls"), event("ls 2")], T0)
    batch = _ingest_holds.read(repo, _ingest_holds.head(repo, "rl"), "opentine.ingest-batch/1")
    ident = _monitor_ledger.identity(config())
    fake = [{"i": i, "a": "allow", "d": "sha256:" + "0" * 64, "l": 0, "s": 0.0}
            for i in range(50)]  # fmt: skip
    _monitor_ledger.append(repo, ident, "rl", {"id": batch["id"], **batch["claim"]}, fake,
                           key("monitor"), threshold=0.5, at="2027-01-15T08:00:00Z")  # fmt: skip
    body = _report(repo)
    assert "fail:monitor.coverage-forged" in _codes(body)
    assert body["evaluated"] == 0


def test_a_changed_threshold_is_a_config_change_and_needs_its_own_validation(repo):
    ingest(repo, [event("ls")], T0)
    _runner(repo).once()
    looser = config(__import__("tests.monitor_ledger_helpers", fromlist=["CONFIG"]).CONFIG
                    .replace("threshold = 0.5", "threshold = 0.95"))  # fmt: skip
    ingest(repo, [event("ls 2")], T0 + 3)
    _runner(repo, looser).once()
    body = _report(repo, looser)
    assert "advisory:monitor.config-changed" in _codes(body, "advisory")
    assert body["covered"] == "2/2"
    rsi = _report(repo, looser, profile="rsi")
    assert "fail:monitor.unvalidated-threshold" in _codes(rsi)
    assert rsi["counts_as_coverage"] is False and rsi["evaluated"] == 0


def test_ledger_heads_cannot_be_released(repo):
    ingest(repo, [event("ls")], T0)
    _runner(repo).once()
    with pytest.raises(HoldError):
        release(repo, _monitor_ledger.head(repo, "rules", "rl"))


def test_the_gate_records_category_and_severity_too(repo):
    from opentine._monitor_gate import Gate

    gate = Gate(config(), repo=repo, key=key("monitor"), clock=lambda: 0.0,
                wall=lambda: T0 / 1000)  # fmt: skip
    out = gate.decide("tools/call", {"name": "shell", "arguments": {"cmd": "rm -rf /"}})
    assert out["claim"]["category"] == "destructive" and out["claim"]["severity"] == "high"
    quiet = gate.decide("tools/call", {"name": "shell", "arguments": {"cmd": "ls"}})
    assert "category" not in quiet["claim"]
