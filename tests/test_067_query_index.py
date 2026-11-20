"""0.65 ``tine query``: the derived index, its oids, staleness and the read-only guard."""

from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest

from opentine import _query_index, _schemas
from opentine._query_rows import COLUMNS
from opentine._query_sql import QueryError, run
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.query_helpers import add_run, build, tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


@pytest.fixture
def room(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return build(tmp_path)


def _rebuild(capsys, *extra: str) -> dict:
    code, body = tine(capsys, "query", "index", "--rebuild", "--repo", "r", *extra)
    assert code == 0, body
    return body


def test_the_index_holds_every_table_and_every_row_names_its_oid(capsys, room):
    body = _rebuild(capsys, "--evals", "ev")
    _schemas.validate(body, "tine-cli-query-1")
    assert body["authority"] == "non-authoritative" and body["stale"] is False
    assert body["counts"] == {"runs": 3, "steps": 6, "monitor_verdicts": 2,
                              "oversight_decisions": 0, "lineage_variants": 0,
                              "lineage_edges": 0, "evals": 4, "experiments": 0,
                              "experiment_results": 0, "reproductions": 0, "sabotage_tasks": 0,
                              "elicit_links": 0, "elicit_items": 0,
                              "history_merges": 0, "sandbox_policies": 0,
                              "containment_findings": 0, "budget_ledger": 0,
                              "weight_custody": 0, "organism_records": 0, "uplift_suites": 0,
                              "uplift_records": 0, "trend_points": 0}  # fmt: skip
    path = room["repo"].path / "query" / "index.sqlite"
    with closing(sqlite3.connect(path)) as db:
        for table in COLUMNS:
            assert db.execute(f"SELECT COUNT(*) FROM {table} WHERE oid IS NULL").fetchone() == (0,)
        meta = dict(db.execute("SELECT key, value FROM meta"))
    assert meta["authority"] == "non-authoritative"
    assert sorted(r["oid"] for r in run(path, "SELECT oid FROM runs")["rows"]) == sorted(
        room["runs"]
    )


def test_an_aggregate_reads_the_costs_view(capsys, room):
    code, body = tine(
        capsys,
        "query",
        "SELECT model, COUNT(*) AS n, SUM(cost) AS total, "
        "SUM(input_tokens) AS tin FROM costs GROUP BY model",
        "--repo",
        "r",
    )
    assert code == 0, body
    _schemas.validate(body, "tine-cli-query-1")
    assert body["rows"] == [{"model": "m1", "n": 6, "total": 1.5, "tin": 30}]
    assert body["authority"] == "non-authoritative" and body["verification"] is None


@pytest.mark.parametrize("sql", [
    "DELETE FROM runs", "UPDATE runs SET status = 'x'", "INSERT INTO meta VALUES ('a', 'b')",
    "DROP TABLE runs", "CREATE TABLE t (a)", "ATTACH DATABASE 'x.db' AS x",
    "PRAGMA writable_schema = 1", "PRAGMA query_only = 0", "PRAGMA table_info(runs)",
    "SELECT load_extension('x')", "BEGIN", "VACUUM", "REINDEX",
    "SELECT 1; DELETE FROM runs", "CREATE TEMP VIEW v AS SELECT 1",
])  # fmt: skip
def test_only_reading_is_allowed(capsys, room, sql):
    _rebuild(capsys)
    path = room["repo"].path / "query" / "index.sqlite"
    before = path.read_bytes()
    with pytest.raises(QueryError) as caught:
        run(path, sql)
    assert caught.value.code in ("query.refused", "query.sql")
    assert path.read_bytes() == before
    code, body = tine(capsys, "query", sql, "--repo", "r")
    assert code == 1 and "error" in body
    assert path.read_bytes() == before


def test_work_is_bounded_by_a_step_count_not_a_clock(capsys, room):
    _rebuild(capsys)
    path = room["repo"].path / "query" / "index.sqlite"
    endless = "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n) SELECT max(i) FROM n"
    with pytest.raises(QueryError) as caught:
        run(path, endless, max_steps=50)
    assert caught.value.code == "query.too-many-steps"
    counted = "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 500) "
    assert run(path, counted + "SELECT COUNT(*) AS c FROM n")["rows"] == [{"c": 500}]


def test_limit_truncates_and_says_so(capsys, room):
    code, body = tine(capsys, "query", "SELECT oid FROM steps ORDER BY oid", "--limit", "2",
                      "--repo", "r")  # fmt: skip
    assert code == 0 and len(body["rows"]) == 2 and body["truncated"] is True


def test_a_new_run_makes_the_index_stale_and_refresh_rebuilds(capsys, room):
    _rebuild(capsys)
    add_run(room["repo"], "late", cost=1.0)
    code, body = tine(capsys, "query", "SELECT COUNT(*) AS n FROM runs", "--repo", "r")
    assert code == 0 and body["stale"] is True and body["rows"] == [{"n": 3}]
    assert body["stale_reasons"] == ["objects were added or removed since the build"]
    code, body = tine(capsys, "query", "SELECT COUNT(*) AS n FROM runs", "--refresh",
                      "--repo", "r")  # fmt: skip
    assert body["stale"] is False and body["rows"] == [{"n": 4}]


def test_an_edited_eval_folder_makes_the_index_stale(capsys, room):
    _rebuild(capsys, "--evals", "ev")
    code, body = tine(capsys, "query", "index", "--repo", "r")
    assert body["stale"] is False and body["evals"] == [room["evals"].resolve().as_posix()]
    path = room["evals"] / "verdicts.jsonl"
    path.write_bytes(path.read_bytes() + b"\n")
    code, body = tine(capsys, "query", "index", "--repo", "r")
    assert body["stale"] is True and body["reasons"] == ["an eval folder changed"]


def test_the_index_is_built_on_first_query_and_deleting_it_loses_nothing(capsys, room):
    sql = "SELECT oid, steps FROM runs ORDER BY oid"
    code, first = tine(capsys, "query", sql, "--repo", "r")
    assert code == 0 and len(first["rows"]) == 3
    _query_index.index_path(room["repo"].path).unlink()
    code, again = tine(capsys, "query", sql, "--repo", "r")
    assert again["rows"] == first["rows"]


def test_worker_processes_index_the_same_rows(room):
    from opentine._query_build import build

    path = room["repo"].path / "query" / "index.sqlite"
    sql = "SELECT * FROM steps ORDER BY run, seq"
    build(room["repo"], workers=1)
    serial = run(path, sql)["rows"] + run(path, "SELECT * FROM monitor_verdicts")["rows"]
    build(room["repo"], workers=2)
    assert run(path, sql)["rows"] + run(path, "SELECT * FROM monitor_verdicts")["rows"] == serial


def test_a_repack_with_the_same_objects_is_not_stale(capsys, room):
    from opentine._query_build import staleness

    _rebuild(capsys)
    store = room["repo"].path
    _query_index.set_meta(_query_index.index_path(store), "fingerprint", "0" * 64)
    assert staleness(room["repo"])["stale"] is False
    meta = _query_index.read_meta(_query_index.index_path(store))
    assert meta["fingerprint"] == _query_index.fingerprint(store)
