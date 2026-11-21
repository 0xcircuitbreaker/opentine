"""0.73 acceptance, end to end: uplift records and trend points in ``tine query``,
trend points joined to 0.58 lineage generations, and fail-closed behaviour.

One repository holds the three-generation lineage of the trends tests, an
uplift suite and records that name the same generations. The index must show
the same generations and point estimates ``tine trends`` reports, ``--verify``
must re-derive every row, a doctored row must fail, and an optimizer key must
not be able to sign an uplift record.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from decimal import Decimal
from pathlib import Path

import pytest

from opentine import _schemas, _uplift
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.lineage_helpers import RECORDER
from tests.promote_helpers import EVALER, key
from tests.query_helpers import add_run, tine
from tests.trends_helpers import build, roles_toml

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
AT = "2026-12-01T10:00:00Z"
SUITE = {"name": "toy", "version": "1", "scoring": "binary",
         "tasks": [{"id": f"t{i}", "minutes": str(2**i)} for i in range(4)]}  # fmt: skip


@pytest.fixture
def room(tmp_path: Path) -> dict:
    root, variants = build(tmp_path)
    repo = Repo.open(root)
    run = add_run(repo, "uplift-run", cost=0.1)
    digest = _uplift.suite_digest(SUITE)
    _uplift.record(repo, run, {"convention": _uplift.SUITE, "digest": digest, "suite": SUITE,
                               "at": AT}, key(EVALER))  # fmt: skip
    for gen in range(3):
        for i, task in enumerate(SUITE["tasks"]):
            claim = {"convention": _uplift.RECORD, "record": "run", "suite": digest,
                     "task": task["id"], "subject": "model-a", "condition": "ai",
                     "success": i <= gen, "minutes": None, "perceived_minutes": None,
                     "generation": gen, "at": AT}  # fmt: skip
            _uplift.record(repo, run, claim, key(EVALER))
    return {"root": root, "repo": repo, "run": run, "suite": digest, "v": variants,
            "args": ("--repo", root.as_posix())}  # fmt: skip


def _rows(capsys, room: dict, sql: str, *extra: str) -> tuple[int, dict]:
    return tine(capsys, "query", sql, *room["args"], *extra)


def test_trend_points_and_uplift_records_are_queryable_and_join_lineage(room, capsys) -> None:
    code, body = tine(capsys, "query", "index", "--rebuild", *room["args"])
    assert code == 0, body
    _schemas.validate(body, "tine-cli-query-1")
    assert body["counts"]["trend_points"] == 3 and body["counts"]["uplift_suites"] == 1
    assert body["counts"]["uplift_records"] == 12
    code, out = _rows(capsys, room, "SELECT t.variant, t.generation, t.n, t.score, t.pass_rate,"
                      " t.withheld, COUNT(e.parent) AS parents FROM trend_points t"
                      " JOIN lineage_variants l ON l.variant = t.variant"
                      " LEFT JOIN lineage_edges e ON e.child = t.variant"
                      " GROUP BY t.variant ORDER BY t.generation")  # fmt: skip
    assert code == 0, out
    got = {r["variant"]: r for r in out["rows"]}
    v = room["v"]
    assert [got[v[n]]["generation"] for n in ("root", "child", "worse")] == [0, 1, 2]
    assert [got[v[n]]["parents"] for n in ("root", "child", "worse")] == [0, 1, 1]
    capsys.readouterr()
    code, trends = tine(capsys, "trends", *room["args"], "--resamples", "100")
    assert code == 0, trends
    for row in trends["variants"]:
        point = got[row["variant"]]
        assert point["generation"] == row["generation"] and point["n"] == row["n"]
        assert Decimal(point["score"]) == Decimal(row["score"]["mean"])
        assert Decimal(point["pass_rate"]) == Decimal(row["pass_rate"]["mean"])
        assert point["withheld"] == 0
    # uplift records name the same generations: success per generation rises
    code, out = _rows(capsys, room, "SELECT generation, SUM(success) AS ok FROM uplift_records"
                      " WHERE suite = '" + room["suite"] + "' GROUP BY generation"
                      " ORDER BY generation")  # fmt: skip
    assert code == 0 and [(r["generation"], r["ok"]) for r in out["rows"]] == [
        (0, 1), (1, 2), (2, 3)]  # fmt: skip


def test_verify_rederives_every_row_and_a_doctored_point_fails(room, capsys) -> None:
    assert tine(capsys, "query", "index", "--rebuild", *room["args"])[0] == 0
    code, out = _rows(capsys, room, "SELECT * FROM uplift_records", "--verify")
    assert code == 0, out
    assert {c["status"] for c in out["verification"]["rows"]} == {"verified"}
    code, out = _rows(capsys, room, "SELECT * FROM trend_points", "--verify")
    assert code == 0, out
    assert {c["status"] for c in out["verification"]["rows"]} == {"verified"}
    path = room["repo"].path / "query" / "index.sqlite"
    with closing(sqlite3.connect(path)) as db:
        db.execute("UPDATE trend_points SET score = '0.99' WHERE generation = 2")
        db.commit()
    code, out = _rows(capsys, room, "SELECT * FROM trend_points WHERE generation = 2",
                      "--verify")  # fmt: skip
    assert code == 1
    assert out["verification"]["rows"][0]["status"] == "failed"
    assert "score" in out["verification"]["rows"][0]["reason"]


def test_unpinned_roles_withhold_points_and_mark_the_index_stale(room, capsys) -> None:
    assert tine(capsys, "query", "index", "--rebuild", *room["args"])[0] == 0
    store = Path(room["repo"].path)
    roles = "".join(
        line for line in roles_toml().splitlines(keepends=True) if not line.startswith("scorer")
    )  # no scorer role any more
    (store / "key-roles.toml").write_bytes(roles.encode("utf-8"))
    pin_roles(store)
    code, body = tine(capsys, "query", "index", *room["args"])
    assert code == 0 and body["stale"] is True
    assert "the pinned key roles changed" in body["reasons"]
    assert tine(capsys, "query", "index", "--rebuild", *room["args"])[0] == 0
    code, out = _rows(capsys, room, "SELECT withheld, n, score FROM trend_points")
    assert (
        code == 0
        and out["rows"]
        and all(r["withheld"] == 1 and r["n"] == 0 and r["score"] is None for r in out["rows"])
    )


def test_an_optimizer_key_cannot_add_an_uplift_record(room) -> None:
    claim = {"convention": _uplift.RECORD, "record": "run", "suite": room["suite"],
             "task": "t0", "subject": "model-a", "condition": "ai", "success": True,
             "minutes": None, "perceived_minutes": None, "generation": 2, "at": AT}  # fmt: skip
    with pytest.raises(ValueError, match="key-separation"):
        _uplift.record(room["repo"], room["run"], claim, key(RECORDER))
