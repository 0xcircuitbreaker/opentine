"""0.91: the fleet-wide fail-closed stop -- freshness, binding, replay and rollback.

Every decision is driven by an injected clock and the order of channel writes;
nothing sleeps and nothing reads the wall clock.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from opentine import _stop_channel, _stop_ops, _stop_policy, _stop_proof
from opentine._stop_guard import Halt, StopGuard, Watchdog
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401 - autouse
from tests.stop_helpers import (
    FLEET,
    OPT,
    POLICY,
    RUNNER,
    Clock,
    fleet,
    halt_fleet,
    keep_going,  # fmt: skip
    key,
    make_repo,
)


def guard(repo, run: str, clock: Clock) -> StopGuard:
    return StopGuard(_stop_policy.load(repo), Path(repo.path), run, clock_ms=clock)


def code(g: StopGuard) -> str:
    with pytest.raises(Halt) as caught:
        g.check()
    return caught.value.code


def test_a_stop_issued_at_one_repository_blocks_the_next_check_at_all_three(tmp_path):
    clock = Clock()
    channel, repos = fleet(tmp_path, 3)
    runs = ["run-a", "run-b", "run-c"]
    keep_going(repos[0], channel, runs, clock)
    guards = [guard(repo, run, clock) for repo, run in zip(repos, runs)]
    assert [g.check()["seq"] for g in guards] == [1, 1, 1]
    stop = halt_fleet(repos[1], channel, clock)
    clock.advance(1)  # well inside the window: the stop, not staleness, halts them
    for g in guards:
        with pytest.raises(Halt) as caught:
            g.check()
        assert caught.value.code == "stop.stopped" and caught.value.stop == stop["attestation"]
    with pytest.raises(ValueError, match="stopped"):  # and no continue proof can follow it
        keep_going(repos[0], channel, runs[:1], clock)


def test_a_stale_proof_halts_within_the_window_and_a_fresh_one_does_not(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path, window_s=300)
    keep_going(repo, channel, ["r"], clock)
    assert guard(repo, "r", clock).check()["age_ms"] == 0
    clock.advance(300)
    assert guard(repo, "r", clock).check()["age_ms"] == 300_000  # exactly T is still fresh
    clock.advance(1)
    g = guard(repo, "r", clock)
    assert code(g) == "stop.continue-stale"
    keep_going(repo, channel, ["r"], clock)
    assert code(g) == "stop.continue-stale"  # a halted guard stays halted
    assert guard(repo, "r", clock).check()["seq"] == 2


def test_the_smaller_window_wins_so_a_rewritten_policy_cannot_widen_it(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path, window_s=3600)
    keep_going(repo, channel, ["r"], clock, window_s=60)
    clock.advance(61)
    assert code(guard(repo, "r", clock)) == "stop.continue-stale"


def test_an_unreachable_channel_blocks(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path)
    keep_going(repo, channel, ["r"], clock)
    g = guard(repo, "r", clock)
    g.check()
    channel.rename(tmp_path / "gone")
    assert code(g) == "stop.channel-unreachable"
    assert code(guard(repo, "r", clock)) == "stop.channel-unreachable"


def test_a_rolled_back_channel_is_refused(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path)
    keep_going(repo, channel, ["r"], clock)
    copy = tmp_path / "copy"
    shutil.copytree(channel, copy)
    keep_going(repo, channel, ["r"], clock)  # the log grows ...
    g = guard(repo, "r", clock)
    assert g.check()["seq"] == 2
    shutil.rmtree(channel)
    shutil.copytree(copy, channel)  # ... and someone puts the old log back
    assert guard(repo, "r", clock).check()["seq"] == 1  # a fresh reader cannot know
    assert code(g) == "stop.channel-rollback"  # one that read the longer log does


def test_a_proof_for_another_run_or_fleet_is_not_a_proof(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path)
    keep_going(repo, channel, ["other-run"], clock)
    assert code(guard(repo, "r", clock)) == "stop.no-continue"
    other = tmp_path / "other-channel"
    _stop_channel.init(other, "fleet-b")
    _stop_ops.issue_continue(repo, other, "fleet-b", ["r"], key(POLICY), window_s=300,
                             now_ms=clock())  # fmt: skip
    assert code(guard(repo, "r", clock)) == "stop.no-continue"


def test_a_proof_copied_from_another_channel_is_unbound(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path)
    twin = tmp_path / "twin"
    _stop_channel.init(twin, FLEET)  # same fleet id, another log key
    row = _stop_ops.issue_continue(repo, twin, FLEET, ["r"], key(POLICY), window_s=300,
                                   now_ms=clock())[0]  # fmt: skip
    payload = repo.get(row["attestation"]).payload()
    _stop_channel.append(channel, FLEET, "continue", row["attestation"], payload)
    assert code(guard(repo, "r", clock)) == "stop.continue-unbound"


def test_a_future_dated_proof_is_refused(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path)
    ahead = Clock()
    ahead.advance(31)  # beyond the 30 s skew
    keep_going(repo, channel, ["r"], ahead)
    assert code(guard(repo, "r", clock)) == "stop.continue-future"


def test_optimizer_and_unpinned_keys_neither_issue_nor_count(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path)
    for seed in (OPT, RUNNER):
        with pytest.raises(ValueError, match="pinned stopper or policy"):
            keep_going(repo, channel, ["r"], clock, seed=seed)
    # a proof signed by the optimizer and appended by hand is ignored
    claim = _stop_proof.continue_claim(FLEET, "r", 9, _stop_proof.rfc3339(clock()), 300,
                                       _stop_policy.load(repo)["vkey"],
                                       _stop_channel.snapshot(channel, FLEET,
                                       _stop_policy.load(repo)["vkey"]).checkpoint())  # fmt: skip
    oid, payload = _stop_proof.sign(repo, claim, key(OPT), "continue")
    _stop_channel.append(channel, FLEET, "continue", oid, payload)
    assert code(guard(repo, "r", clock)) == "stop.no-continue"
    unpinned = make_repo(tmp_path / "unpinned", pinned=False)
    with pytest.raises(ValueError, match="unpinned"):
        keep_going(unpinned, channel, ["r"], clock)


def test_an_edited_payload_does_not_verify(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path)
    row = keep_going(repo, channel, ["r"], clock)[0]
    forged = repo.get(row["attestation"]).payload()
    forged = {**forged, "claim": {**forged["claim"], "run": "r2", "seq": 5}}
    _stop_channel.append(channel, FLEET, "continue", row["attestation"], forged)
    assert code(guard(repo, "r2", clock)) == "stop.no-continue"


def test_a_lower_sequence_after_a_higher_one_is_a_rollback(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path)
    keep_going(repo, channel, ["r"], clock)
    g = guard(repo, "r", clock)
    g.check()
    g._seq = 7  # as if seq 7 had been accepted from a log this one no longer holds
    assert code(g) == "stop.continue-rollback"


def test_a_stop_halts_even_when_its_signature_does_not_verify(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path)
    keep_going(repo, channel, ["r"], clock)
    _stop_channel.append(channel, FLEET, "stop", "attestation:sha256:" + "0" * 64, {"claim": {}})
    assert code(guard(repo, "r", clock)) == "stop.stopped"


def test_the_policy_cannot_be_deleted_or_edited_away(tmp_path):
    channel, (repo,) = fleet(tmp_path)
    path = _stop_policy.path(repo)
    text = path.read_bytes()
    path.write_bytes(text.replace(b'"window_s":300', b'"window_s":86400'))
    with pytest.raises(_stop_policy.StopPolicyError, match="differs"):
        _stop_policy.load(repo)
    path.unlink()
    with pytest.raises(_stop_policy.StopPolicyError, match="missing"):
        _stop_policy.load(repo)
    path.write_bytes(text)
    assert _stop_policy.load(repo)["window_s"] == 300
    assert _stop_policy.load(make_repo(tmp_path / "plain")) is None  # no policy: no change


def test_the_watchdog_halts_a_long_step_once(tmp_path):
    clock = Clock()
    channel, (repo,) = fleet(tmp_path)
    keep_going(repo, channel, ["r"], clock)
    seen: list[str] = []
    dog = Watchdog(guard(repo, "r", clock), lambda halt: seen.append(halt.code), 10)
    assert dog.tick() is False
    clock.advance(301)
    assert dog.tick() is True and dog.tick() is True
    assert seen == ["stop.continue-stale"]
