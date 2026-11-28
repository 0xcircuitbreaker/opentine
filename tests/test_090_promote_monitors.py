"""R6: ``tine promote`` reads monitor coverage for the candidate's runs (0.90)."""

from __future__ import annotations

import pytest

from opentine import _monitor_ledger, _monitor_validation, _promote_monitors, _promote_skill
from opentine._monitor_runner import Runner
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.monitor_ledger_helpers import (  # noqa: F401
    CONFIG,
    T0,
    config,
    event,
    fpr,
    ingest,
    key,
    pin_monitors,
    repo_fixture,
)
from tests.test_090_monitor_operating_point import _labelled

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
CANDIDATE = "run:sha256:" + "ab" * 32
MIN = 60_000
REQUIRED = {"monitor_coverage": "required", "required_monitors": ["rules"]}


def _mine(cmd: str = "ls") -> dict:
    return event(cmd, run=CANDIDATE)


def _validate(repo, text=CONFIG) -> None:
    cfg = config(text)
    point = _monitor_validation.evaluate(cfg, _labelled())
    _monitor_validation.record(repo, _monitor_ledger.identity(cfg), point, key("scorer"),
                               "2027-01-15T08:00:00Z")  # fmt: skip


def _watched(repo, at: int, name: str = "monitor", text: str = CONFIG) -> Runner:
    runner = Runner(repo, config(text), "rl", key(name), clock_ms=lambda: at)
    runner.once()
    runner.heartbeat()
    return runner


def _refusals(repo, policy=None) -> list[str]:
    found, _ = _promote_monitors.findings(policy or REQUIRED, repo.path, CANDIDATE)
    return [r["detail"] for r in found]


def _good(repo) -> None:
    _validate(repo)
    Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0 - 1_000).heartbeat()
    ingest(repo, [_mine("ls"), event("ls", run="other")], T0)
    _watched(repo, T0 + 1_000)


def test_a_fully_watched_candidate_promotes(repo):
    _good(repo)
    assert _refusals(repo) == []


def test_promote_refuses_an_unwatched_candidate(repo):
    _validate(repo)
    ingest(repo, [_mine()], T0)
    assert any("were not evaluated by rules" in d for d in _refusals(repo))
    # the gate is wired into promote's gates: the refusal is promote.monitor-coverage
    held, _, _ = _promote_skill.gates({"regions": "advisory", **REQUIRED}, repo.path,
                                      CANDIDATE, None, "prod", None)  # fmt: skip
    assert "promote.monitor-coverage" in {r["code"] for r in held}


def test_promote_refuses_coverage_without_a_validated_operating_point(repo):
    Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0 - 1_000).heartbeat()
    ingest(repo, [_mine()], T0)
    _watched(repo, T0 + 1_000)
    assert any("no validated operating point" in d for d in _refusals(repo))


def test_promote_refuses_a_monitor_stale_over_the_run_window(repo):
    _validate(repo)
    Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0 - 1_000).heartbeat()
    ingest(repo, [_mine("ls 1")], T0)
    runner = Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0 + 1_000)
    runner.once()
    ingest(repo, [_mine("ls 2")], T0 + 10 * MIN)  # same run; the monitor stopped beating
    runner.clock_ms = lambda: T0 + 10 * MIN + 1_000
    runner.once()  # evaluated late, but no heartbeat in between
    assert any("stale" in d for d in _refusals(repo))


def test_a_single_batch_window_with_an_old_heartbeat_is_stale(repo):
    # Off by one: a run whose window is one instant still needs a live monitor at it.
    _validate(repo)
    Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0 - 10 * MIN).heartbeat()
    ingest(repo, [_mine()], T0)
    Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0 + 1_000).once()
    assert any("stale" in d for d in _refusals(repo))


def test_a_heartbeat_exactly_at_the_window_start_is_live(repo):
    _validate(repo)
    ingest(repo, [_mine()], T0)
    Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0).heartbeat()
    Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0 + 1_000).once()
    assert _refusals(repo) == []


def test_a_heartbeat_just_after_the_window_start_is_not(repo):
    _validate(repo)
    ingest(repo, [_mine()], T0)
    _watched(repo, T0 + 1_000)  # times are whole seconds: the next one
    assert any("stale" in d for d in _refusals(repo))


def test_a_pinned_required_monitor_cannot_be_marked_not_required(repo):
    pin_monitors(repo, {"rules": [fpr("monitor")]}, required=["rules"])
    ingest(repo, [_mine()], T0)
    advisory = {"monitor_coverage": "advisory", "required_monitors": []}
    assert _refusals(repo, advisory)  # the bundle's rule holds whatever [promote] says


def test_advisory_by_default_and_nothing_without_a_required_monitor(repo):
    ingest(repo, [_mine()], T0)
    refusals, advisories = _promote_monitors.findings(
        {"monitor_coverage": "advisory", "required_monitors": ["rules"]}, repo.path, CANDIDATE
    )
    assert refusals == [] and {a["code"] for a in advisories} == {
        "advisory:promote.monitor-coverage"}  # fmt: skip
    assert _promote_monitors.findings({"monitor_coverage": "required"}, repo.path,
                                      CANDIDATE) == ([], [])  # fmt: skip


def test_rsi_requires_monitor_coverage(repo):
    with pytest.raises(ValueError, match="rsi"):
        _promote_monitors.check_policy({"profile": "rsi", "monitor_coverage": "advisory"})
    policy = {"profile": "rsi"}
    _promote_monitors.check_policy(policy)
    assert policy["monitor_coverage"] == "required"


def test_a_candidate_no_ingest_event_names_is_refused(repo):
    _good(repo)
    found, _ = _promote_monitors.findings(REQUIRED, repo.path, "run:sha256:" + "cd" * 32)
    assert any("no captured ingest event" in r["detail"] for r in found)


def test_coverage_by_another_monitors_key_or_a_renamed_id_does_not_count(repo):
    _validate(repo)
    Runner(repo, config(), "rl", key("monitor2"), clock_ms=lambda: T0 - 1_000).heartbeat()
    ingest(repo, [_mine()], T0)
    _watched(repo, T0 + 1_000, name="monitor2")  # key reuse: a pinned key bound elsewhere
    assert any("coverage-unsigned" in d for d in _refusals(repo))
    renamed = CONFIG.replace('id = "rules"', 'id = "rules2"')
    _validate(repo, renamed)
    _watched(repo, T0 + 2_000, text=renamed)
    assert any("signer-unbound" in d for d in _refusals(repo, {
        "monitor_coverage": "required", "required_monitors": ["rules2"]}))  # fmt: skip


def test_deleting_the_bundle_does_not_drop_a_pinned_required_monitor(repo):
    _good(repo)
    pin_monitors(repo, {"rules": [fpr("monitor")]}, required=["rules"])
    (repo.path / "trust-bundle.note").unlink()
    found, _ = _promote_monitors.findings({"monitor_coverage": "advisory"}, repo.path, CANDIDATE)
    assert [r["code"] for r in found] == ["promote.monitor-coverage"]


def test_a_lookalike_spelling_of_the_candidate_run_is_still_the_candidate(repo):
    _good(repo)
    wide = "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in CANDIDATE.upper())
    ingest(repo, [event("rm -rf /", run=wide)], T0 + 5_000)  # never evaluated
    assert any("were not evaluated" in d for d in _refusals(repo))
