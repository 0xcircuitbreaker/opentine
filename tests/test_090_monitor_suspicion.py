"""Cumulative suspicion and doom-loop flags against hostile loops; oversight routing."""

from __future__ import annotations

import pytest

from opentine import _monitor_ledger, _monitor_suspicion, _oversight_queue
from opentine._monitor_runner import Runner
from opentine._monitor_verdict import monitors
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.monitor_ledger_helpers import T0, config, event, ingest, key, repo_fixture  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _scan(repo, name: str = "monitor") -> dict:
    Runner(repo, config(), "rl", key(name), clock_ms=lambda: T0 + 1_000).once()
    return _monitor_suspicion.scan(repo, _monitor_ledger.chains(repo), monitors(repo)[0])


def _flags(body: dict) -> set[tuple[str, str]]:
    return {(f["code"].split(".", 1)[1], f["subject"]) for f in body["flags"]}


def test_probing_just_under_the_threshold_across_sessions_is_a_doom_loop(repo):
    # Each session stays under every per-session limit; the agent does not.
    for n in range(3):
        ingest(repo, [event(f"probe {n}", session=f"s{n}", run=f"r{n}")], T0 + n)
    body = _scan(repo)
    assert ("doom-loop-near-threshold", "agent:a1") in _flags(body)
    assert not any(s.startswith("session:") for _, s in _flags(body))


def test_rotating_agent_ids_does_not_reset_the_session_total(repo):
    events = [event(f"probe {n}", agent=f"a{n}") for n in range(7)]
    ingest(repo, events, T0)
    flags = _flags(_scan(repo))
    assert ("cumulative-suspicion", "session:s1") in flags
    assert not any(s.startswith("agent:") for _, s in flags)


def test_retrying_the_same_refused_action_under_new_identities_is_flagged(repo):
    for n in range(3):
        ingest(repo, [event("rm -rf /", agent=f"x{n}", session=f"y{n}", run=f"z{n}")], T0 + n)
    flags = _flags(_scan(repo))
    assert any(code == "doom-loop-repeated-failure" and s.startswith("action:")
               for code, s in flags)  # fmt: skip


def test_benign_traffic_raises_nothing(repo):
    ingest(repo, [event(f"ls {n}") for n in range(50)], T0)
    assert _scan(repo)["flags"] == []


def test_flags_from_an_unpinned_ledger_are_ignored(repo):
    for n in range(3):
        ingest(repo, [event(f"probe {n}")], T0 + n)
    assert _scan(repo, "stranger")["flags"] == []


def test_flags_open_oversight_items(repo):
    for n in range(3):
        ingest(repo, [event(f"probe {n}")], T0 + n)
    _scan(repo)
    found = _monitor_suspicion.items(repo)
    assert found and all(i["item"].startswith("suspicion:annotation:sha256:") for i in found)
    sources = {row["source"] for row in _oversight_queue._sources(repo)}
    assert "suspicion" in sources
