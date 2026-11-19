"""0.65 ``tine query --verify``: each returned row goes back to its object."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing

import pytest

from opentine import _schemas
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.query_helpers import build, tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


@pytest.fixture
def room(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    found = build(tmp_path)
    code, body = tine(capsys, "query", "index", "--rebuild", "--evals", "ev", "--repo", "r")
    assert code == 0, body
    return found


def _statuses(body: dict) -> dict[str, str]:
    return {c["oid"]: c["status"] for c in body["verification"]["rows"]}


def _tamper(room: dict, sql: str, args: tuple) -> None:
    path = room["repo"].path / "query" / "index.sqlite"
    with closing(sqlite3.connect(path)) as db:
        db.execute(sql, args)
        db.commit()


def test_a_pinned_monitor_verdict_verifies_and_an_unpinned_one_does_not(capsys, room):
    code, body = tine(capsys, "query", "SELECT oid, action, signer FROM monitor_verdicts",
                      "--verify", "--repo", "r")  # fmt: skip
    assert code == 0, body
    _schemas.validate(body, "tine-cli-query-1")
    assert _statuses(body) == {room["pinned"]: "verified", room["other"]: "unverified"}
    pinned = next(c for c in body["verification"]["rows"] if c["oid"] == room["pinned"])
    assert pinned["roles"] == ["monitor"]
    code, _ = tine(capsys, "query", "SELECT oid FROM monitor_verdicts", "--verify", "--strict",
                   "--repo", "r")  # fmt: skip
    assert code == 1  # --strict: an unverified row blocks


def test_runs_and_steps_are_intact_but_unsigned(capsys, room):
    code, body = tine(capsys, "query", "SELECT oid, kind, cost FROM steps", "--verify",
                      "--repo", "r")  # fmt: skip
    assert code == 0
    assert body["verification"]["counts"] == {"verified": 0, "unverified": 6, "failed": 0}
    assert {c["reason"] for c in body["verification"]["rows"]} == {"content-addressed, not signed"}


def test_an_edited_index_row_fails(capsys, room):
    _tamper(room, "UPDATE monitor_verdicts SET action = 'allow' WHERE oid = ?", (room["pinned"],))
    code, body = tine(capsys, "query", "SELECT oid, action FROM monitor_verdicts", "--verify",
                      "--repo", "r")  # fmt: skip
    assert code == 1
    check = next(c for c in body["verification"]["rows"] if c["oid"] == room["pinned"])
    assert check["status"] == "failed"
    assert check["reason"] == "the index row disagrees with the source on action"


def test_a_cost_edited_in_the_index_fails(capsys, room):
    _tamper(room, "UPDATE steps SET cost = 0 WHERE seq = 0 AND run = ?", (room["runs"][2],))
    code, body = tine(capsys, "query", "SELECT oid, cost FROM costs WHERE run = ?".replace(
        "?", f"'{room['runs'][2]}'"), "--verify", "--repo", "r")  # fmt: skip
    assert code == 1
    assert body["verification"]["counts"]["failed"] == 1


def test_an_oid_with_no_object_fails(capsys, room):
    ghost = "run:sha256:" + "0" * 64
    _tamper(room, "UPDATE runs SET oid = ? WHERE oid = ?", (ghost, room["runs"][0]))
    code, body = tine(capsys, "query", "SELECT oid FROM runs", "--verify", "--repo", "r")
    assert code == 1 and _statuses(body)[ghost] == "failed"


def test_eval_verdicts_verify_against_their_file(capsys, room):
    code, body = tine(capsys, "query", "SELECT oid, item, score, passed FROM evals",
                      "--verify", "--repo", "r")  # fmt: skip
    assert code == 0, body
    assert set(_statuses(body).values()) == {"verified"}
    path = room["evals"] / "verdicts.jsonl"
    lines = path.read_bytes().split(b"\n")
    verdict = json.loads(lines[0])
    verdict["score"] = "0" if verdict["score"] != "0" else "1"
    lines[0] = json.dumps(verdict).encode("utf-8")
    path.write_bytes(b"\n".join(lines))
    code, body = tine(capsys, "query", "SELECT oid FROM evals", "--verify", "--repo", "r")
    assert code == 1
    assert body["verification"]["counts"] == {"verified": 3, "unverified": 0, "failed": 1}


def test_a_row_without_an_oid_is_unverified_not_failed(capsys, room):
    code, body = tine(capsys, "query", "SELECT COUNT(*) AS n FROM runs", "--verify",
                      "--repo", "r")  # fmt: skip
    assert code == 0
    assert body["verification"]["rows"] == [{"oid": None, "status": "unverified",
                                             "reason": "the row has no oid", "signer": None,
                                             "roles": []}]  # fmt: skip


def test_without_a_pinned_bundle_nothing_is_verified(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    build(tmp_path, pin=False)
    code, body = tine(capsys, "query", "SELECT oid FROM monitor_verdicts", "--verify",
                      "--repo", "r")  # fmt: skip
    assert code == 0  # D12: unverified is advisory by default
    assert set(_statuses(body).values()) == {"unverified"}


def test_oversight_decisions_are_indexed_and_checked(capsys, room):
    from opentine import _oversight
    from tests.promote_helpers import key

    item = f"monitor:{room['pinned']}"
    oid = _oversight.decide(room["repo"], item, "approve", key("33" * 32), human="ana",
                            at="2026-12-01T11:00:00Z")  # fmt: skip
    code, body = tine(capsys, "query", "SELECT oid, item, decision, human FROM "
                      "oversight_decisions", "--verify", "--refresh", "--repo", "r")  # fmt: skip
    assert code == 0, body
    assert body["rows"] == [{"oid": oid, "item": item, "decision": "approve", "human": "ana"}]
    assert _statuses(body) == {oid: "unverified"}  # signed; the key holds no pinned role
