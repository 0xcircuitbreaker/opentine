"""0.86: holdout query accounting (counting only).

Every signed eval over a sealed holdout adds a signed, held query record for
its lineage node; a commitment's ``max_queries`` flags the queries past it.
Bytes I/O, no sleeps, everything under the test's own ``tmp_path``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine._holdout_query import FLAG, check_policy, counts, over_budget_evals, promote_findings
from tests.holdout_helpers import EVAL, ITEMS, Hold, tine
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


@pytest.fixture
def hold(tmp_path: Path, capsys) -> Hold:
    found = Hold(tmp_path)
    assert found.seal(capsys, "h1", "--max-queries", "2", unseals=3, items=6)[0] == 0
    assert found.unseal(capsys)[0] == 0
    outputs = tmp_path / "outs.jsonl"
    rows = [{"id": i["id"], "output": i["expected"], "run": "run-x"} for i in ITEMS]
    outputs.write_bytes("".join(json.dumps(r) + "\n" for r in rows).encode("utf-8"))
    return found


def _eval(hold: Hold, capsys, n: int, *extra: str, lineage: str = "gen-1") -> dict:
    argv = ["eval", "run", (hold.base / "out" / "released.jsonl").as_posix(), "--outputs",
            (hold.base / "outs.jsonl").as_posix(), "--scorer", "exact", "--key",
            hold.keys[EVAL], "--out", (hold.base / "evals" / f"e{n}").as_posix(), "--repo",
            hold.root.as_posix(), "--created-at", f"2026-11-27T10:00:{n:02d}Z", "--json",
            "--lineage", lineage, *extra]  # fmt: skip
    code, row = tine(capsys, *argv)
    assert code == 0, row
    return row


def test_repeated_queries_raise_the_count_and_cross_the_budget(hold, capsys) -> None:
    named = ("--holdout", hold.folder().as_posix())
    rows = [_eval(hold, capsys, n, *named)["holdout_queries"] for n in range(3)]
    assert [r[0]["count"] for r in rows] == [1, 2, 3]
    assert [r[0]["over_budget"] for r in rows] == [False, False, True]
    assert rows[2][0]["max_queries"] == 2 and rows[2][0]["lineage"] == "gen-1"
    record = json.loads(Path(rows[2][0]["record"]).read_bytes())
    claim = record["claim"]
    assert claim["schema"] == "opentine.holdout.query/1"
    assert claim["revealed"] == {"items": 6, "passed": 6, "mean_score": "1"}
    other = _eval(hold, capsys, 9, *named, lineage="gen-2")["holdout_queries"][0]
    assert other["count"] == 1 and other["over_budget"] is False
    state = counts(hold.folder(), hold.root)
    assert state["lineages"] == {"gen-1": 3, "gen-2": 1} and state["over_budget"] == ["gen-1"]
    code, row = tine(capsys, "dataset", "exposure", hold.folder().as_posix(), "--repo",
                     hold.root.as_posix(), "--json")  # fmt: skip
    assert code == 0 and row["queries"]["over_budget"] == ["gen-1"]  # advisory: ok stays


def test_deleting_query_files_lowers_nothing_and_holds_stay(hold, capsys) -> None:
    for n in range(3):
        _eval(hold, capsys, n)  # no --holdout: found by the commitment's dataset digest
    for path in (hold.folder() / "queries").glob("*.json"):
        path.unlink()
    assert counts(hold.folder(), hold.root)["lineages"] == {"gen-1": 3}
    from opentine.repository._holds import HOLDOUT_QUERY, holds_path, read_holds

    rows = [r for r in read_holds(holds_path(hold.repo)) if r["target"].startswith(HOLDOUT_QUERY)]
    assert len(rows) == 3
    code = tine(capsys, "hold", "release", rows[0]["target"], "--repo", hold.root.as_posix())[0]
    assert code != 0
    assert len(over_budget_evals(hold.root)) == 1


def test_a_forged_or_unsigned_record_does_not_count(hold, capsys) -> None:
    _eval(hold, capsys, 0)
    (hold.folder() / "queries" / "forged.json").write_bytes(
        b'{"claim": {"schema": "opentine.holdout.query/1"}}'
    )
    assert counts(hold.folder(), hold.root)["total"] == 1


def test_promote_flags_advisory_by_default_and_refuses_under_rsi(hold, capsys) -> None:
    for n in range(3):
        _eval(hold, capsys, n)
    plain: dict = {}
    check_policy(plain)
    refused, advised = promote_findings([hold.folder()], hold.root, plain)
    assert refused == [] and [a["code"] for a in advised] == ["advisory:holdout.query-budget"]
    rsi = {"profile": "rsi"}
    check_policy(rsi)
    refused, advised = promote_findings([hold.folder()], hold.root, rsi)
    assert [r["code"] for r in refused] == ["promote.holdout-query-budget"] and advised == []
    with pytest.raises(ValueError, match="rsi profile"):
        check_policy({"profile": "rsi", "holdout_queries": "advisory"})


def test_a_holdout_without_a_query_budget_counts_but_never_flags(tmp_path, capsys) -> None:
    hold = Hold(tmp_path)
    assert hold.seal(capsys, unseals=3, items=6)[0] == 0
    assert hold.unseal(capsys)[0] == 0
    outputs = tmp_path / "outs.jsonl"
    rows = [{"id": i["id"], "output": "wrong", "run": "run-x"} for i in ITEMS]
    outputs.write_bytes("".join(json.dumps(r) + "\n" for r in rows).encode("utf-8"))
    for n in range(4):
        _eval(hold, capsys, n)
    state = counts(hold.folder(), hold.root)
    assert state == {"max_queries": None, "total": 4, "lineages": {"gen-1": 4},
                     "over_budget": []}  # fmt: skip


def test_over_budget_points_are_flagged_in_trends_and_query(tmp_path, capsys) -> None:
    from opentine._holdout import sign
    from opentine._holdout_hold import keep
    from opentine.repository._holds import HOLDOUT_QUERY
    from tests.promote_helpers import EVALER, key
    from tests.trends_helpers import build

    root, v = build(tmp_path)
    summary = json.loads((tmp_path / "eval-worse" / "eval.json").read_bytes())
    claim = {"schema": "opentine.holdout.query/1", "holdout": "h", "root": "ab" * 32,
             "lineage": "gen-2", "eval": summary["eval"], "count": 9, "max_queries": 2,
             "over_budget": True}  # fmt: skip
    data = json.dumps(sign(key(EVALER), claim, "sha256:" + "ab" * 32, "2026-11-27T00:00:00Z"))
    keep(root, f"{HOLDOUT_QUERY}{'ab' * 32}:x", data.encode("utf-8"))
    code, row = tine(capsys, "trends", "--repo", root.as_posix(), "--resamples", "200", "--json")
    assert code == 0
    flagged = {r["variant"] for r in row["variants"] if FLAG in r["flags"]}
    assert flagged == {v["worse"]}
    code, out = tine(capsys, "query", "SELECT variant, flags FROM trend_points", "--repo",
                     root.as_posix(), "--json")  # fmt: skip
    assert code == 0
    got = {r["variant"]: r["flags"] for r in out["rows"]}
    assert FLAG in got[v["worse"]] and FLAG not in got[v["root"]]
