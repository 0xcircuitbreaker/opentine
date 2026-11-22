"""0.77 review: live-tail holes found by red-teaming ``opentine._tail``."""

from __future__ import annotations

import pytest

from opentine import _schemas, _tail
from opentine._tail import Follower


@pytest.fixture
def runs(monkeypatch):
    """Runs held in a dict: ``run:<name>`` -> event ids; every event verifies."""
    table: dict[str, list[str]] = {}
    monkeypatch.setattr(_tail, "_run_events", lambda repo, oid: table.get(oid))
    monkeypatch.setattr(_tail, "check_event", lambda repo, oid: ("verified", {"kind": "model"}))
    return table


def test_a_rewrite_that_keeps_the_last_seen_event_but_drops_an_earlier_one_is_reported(runs):
    runs["run:a"] = ["ev-0", "ev-1-episode", "ev-2"]
    refs = {"heads/main": "run:a"}
    follower = Follower(None, lambda: dict(refs), names=["heads/main"], backlog=3)
    assert [r["event_id"] for r in follower.poll()] == ["ev-0", "ev-1-episode", "ev-2"]
    runs["run:b"] = ["ev-0", "ev-1-other", "ev-2", "ev-3"]
    refs["heads/main"] = "run:b"
    rows = follower.poll()
    assert rows[0]["type"] == "rewrite"
    resumed = Follower(None, lambda: dict(refs), names=["heads/main"], resume=_cursor(runs))
    assert resumed.poll()[0]["type"] == "rewrite"


def _cursor(runs) -> str:
    follower = Follower(None, lambda: {"heads/main": "run:a"}, names=["heads/main"])
    return follower.cursor()


def test_a_suffix_match_of_the_last_event_id_is_not_taken_as_the_same_history(runs):
    runs["run:a"] = ["x" * 40 + "SAMESUFFIX12"]
    refs = {"heads/main": "run:a"}
    cursor = Follower(None, lambda: dict(refs), names=["heads/main"]).cursor()
    runs["run:b"] = ["y" * 40 + "SAMESUFFIX12", "ev-new"]
    refs["heads/main"] = "run:b"
    follower = Follower(None, lambda: dict(refs), names=["heads/main"], resume=cursor)
    assert follower.poll()[0]["type"] == "rewrite"


def test_following_all_says_when_refs_beyond_the_limit_are_not_followed(runs, monkeypatch):
    monkeypatch.setattr(_tail, "MAX_REFS", 3)
    refs = {}
    for index in range(5):
        runs[f"run:{index}"] = [f"ev-{index}"]
        refs[f"heads/a{index}"] = f"run:{index}"
    follower = Follower(None, lambda: dict(refs), backlog=1)
    rows = follower.poll()
    cut = [r for r in rows if r["type"] == "truncated"]
    assert len(cut) == 1 and "2" in cut[0]["detail"]
    assert _schemas.validate(cut[0], "tine-tail-1")[1] == []
    assert [r for r in follower.poll() if r["type"] == "truncated"] == []
