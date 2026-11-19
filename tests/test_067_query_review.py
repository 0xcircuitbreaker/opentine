"""0.65 ``tine query`` review: holes a hostile query author or a loop could use."""

from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest

from opentine._query_sql import QueryError, run
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.promote_helpers import make_eval
from tests.query_helpers import MONITOR_SEED, build, tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


@pytest.fixture
def room(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    found = build(tmp_path)
    code, body = tine(capsys, "query", "index", "--rebuild", "--evals", "ev", "--repo", "r")
    assert code == 0, body
    return found


def _tamper(room: dict, sql: str, args: tuple = ()) -> None:
    with closing(sqlite3.connect(room["repo"].path / "query" / "index.sqlite")) as db:
        db.execute(sql, args)
        db.commit()


def _rows(body: dict) -> list[dict]:
    return body["verification"]["rows"]


def test_an_eval_verdict_signed_by_a_non_scorer_key_is_not_verified(tmp_path, capsys, room):
    make_eval(tmp_path / "ev2", room["runs"][0], lambda i: True, n=2, signer=MONITOR_SEED)
    code, body = tine(capsys, "query", "index", "--rebuild", "--evals", "ev", "--evals", "ev2",
                      "--repo", "r")  # fmt: skip
    assert code == 0, body
    sql = "SELECT oid, signer FROM evals WHERE source LIKE '%ev2/%'"
    code, body = tine(capsys, "query", sql, "--verify", "--repo", "r")
    assert code == 0 and len(_rows(body)) == 2
    assert {c["status"] for c in _rows(body)} == {"unverified"}
    assert {c["reason"] for c in _rows(body)} == {"the signer holds no scorer role"}


def test_an_eval_moved_to_another_run_in_the_index_fails(capsys, room):
    _tamper(room, "UPDATE evals SET run = ?", (room["runs"][2],))
    code, body = tine(capsys, "query", "SELECT oid, run, score FROM evals", "--verify",
                      "--repo", "r")  # fmt: skip
    assert code == 1
    assert {c["status"] for c in _rows(body)} == {"failed"}


def test_a_step_moved_to_another_run_in_the_index_fails(capsys, room):
    _tamper(
        room,
        "UPDATE steps SET run = ?, seq = seq + 100 WHERE run = ?",
        (room["runs"][2], room["runs"][0]),
    )
    sql = f"SELECT oid, run, cost FROM steps WHERE run = '{room['runs'][2]}'"
    code, body = tine(capsys, "query", sql, "--verify", "--repo", "r")
    assert code == 1
    assert [c["status"] for c in _rows(body)].count("failed") == 2


def test_an_eval_source_outside_the_indexed_folders_fails(tmp_path, capsys, room):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "verdicts.jsonl").write_bytes((room["evals"] / "verdicts.jsonl").read_bytes())
    _tamper(room, "UPDATE evals SET source = ?", ((outside / "verdicts.jsonl").as_posix(),))
    code, body = tine(capsys, "query", "SELECT oid FROM evals", "--verify", "--repo", "r")
    assert code == 1
    assert {c["reason"] for c in _rows(body)} == {"the source is not an indexed eval file"}


def test_a_planted_lineage_variant_path_fails(capsys, room):
    _tamper(room, "INSERT INTO lineage_variants VALUES (?, ?, NULL, 0, NULL)",
            ("sha256:" + "1" * 64, "sha256:../../etc/x"))  # fmt: skip
    code, body = tine(capsys, "query", "SELECT oid FROM lineage_variants", "--verify",
                      "--repo", "r")  # fmt: skip
    assert code == 1
    assert _rows(body)[0]["reason"] == "the source cannot be read (ValueError)"


def test_duplicate_column_names_are_refused(capsys, room):
    sql = f"SELECT oid, '{room['pinned']}' AS oid FROM monitor_verdicts"
    code, body = tine(capsys, "query", sql, "--verify", "--repo", "r")
    assert code == 1 and "query.duplicate-column" in body["error"]["message"]


def test_a_huge_value_is_refused_not_allocated(tmp_path):
    path = tmp_path / "i.sqlite"
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE t (x)")
        db.commit()
    for sql in ("SELECT randomblob(500000000)", "SELECT length(zeroblob(900000000))"):
        with pytest.raises(QueryError) as caught:
            run(path, sql)
        assert caught.value.code == "query.too-large"
