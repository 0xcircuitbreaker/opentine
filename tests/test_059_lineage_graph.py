"""0.59 lineage graph half: the derived index, ``graph``, ``why``, ``archive``.

The index reads the same lineage folder ``tine lineage record`` writes and
``tine lineage check`` judges, under the one ``opentine.lineage.variant`` claim.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing

import pytest

from opentine import _lineage_index as index
from opentine import _lineage_query as query
from opentine import _schemas, cli
from opentine._lineage import read_folder
from tests.lineage_helpers import archive, art, raw

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def put(store, n, parents=(), *, signed=True, loop="evo", **extra):
    """A synthetic record for variant ``art(n)``; unsigned drops the signature block."""
    variant = raw(store, {"artifacts": art(n), "parents": list(parents), "loop": loop, **extra})
    if not signed:
        path = store / "variants" / f"{variant[7:]}.json"
        payload = json.loads(path.read_bytes())
        del payload["signature"]
        path.write_bytes(json.dumps(payload, indent=2, sort_keys=True).encode())
    return variant


@pytest.fixture
def dag(tmp_path):
    """v0 <- v1, v0 <- v2, (v1, v2) <- v3 (unsigned), (v3, ghost) <- v4."""
    store = tmp_path / "lineage"
    v = {}
    v[0] = put(store, 100)
    v[1] = put(store, 101, [v[0]])
    v[2] = put(store, 102, [v[0]])
    v[3] = put(store, 103, [v[1], v[2]], signed=False)
    v["ghost"] = "sha256:" + "f" * 64
    v[4] = put(store, 104, [v[3], v["ghost"]])
    return store, v


def tine(capsys, *argv):
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return code, capsys.readouterr().out


def test_why_walks_every_ancestor(dag):
    store, v = dag
    with closing(index.open_index(store)) as db:
        body = query.why(db, v[4])
    assert [a["variant"] for a in body["ancestors"]][0] == v[4]
    assert {a["variant"] for a in body["ancestors"]} == {v[0], v[1], v[2], v[3], v[4]}
    assert body["missing_parents"] == [v["ghost"]] and body["depth"] == 3
    assert {a["variant"]: a["signed"] for a in body["ancestors"]}[v[3]] is False
    assert body["summary"]["loop"] == ["evo"]


def test_why_reaches_the_promotion_evidence_and_carries_the_check(tmp_path, capsys):
    store, v = archive(tmp_path)
    code, out = tine(capsys, "lineage", "why", v["good"], "--dir", str(store), "--json")
    body = json.loads(out)
    assert code == 0 and body["ok"] is True and body["findings"] == []
    assert _schemas.validate_output(body) == []
    summary = body["summary"]
    for kind in ("approver", "eval", "judge", "dataset", "decision", "policy", "mutation"):
        assert summary.get(kind), kind
    code, out = tine(capsys, "lineage", "why", v["unsigned"], "--dir", str(store), "--json")
    body = json.loads(out)
    assert code == 1 and body["ok"] is False and _schemas.validate_output(body) == []
    assert {f["code"] for f in body["findings"]} == {"lineage.evidence-missing"}


def test_archive_counts_signed_variants_and_non_linear_parents(dag):
    store, _v = dag
    with closing(index.open_index(store)) as db:
        totals = query.archive(db, loop="evo")["totals"]
        signed = query.archive(db, signed_only=True)["totals"]
    assert totals == {"variants": 5, "signed": 4, "roots": 1, "leaves": 1, "multi_parent": 2,
                      "max_parents": 2}  # fmt: skip
    assert signed["variants"] == 4


def test_deleting_the_index_rebuilds_an_identical_graph(dag):
    store, _v = dag
    with closing(index.open_index(store)) as db:
        before = index.graph(db)
    index.index_path(store).unlink()
    with closing(index.open_index(store)) as db:
        after = index.graph(db)
    assert after == before and len(before["nodes"]) == 5


def test_a_new_record_makes_the_index_stale_and_it_refreshes(dag):
    store, v = dag
    with closing(index.open_index(store)) as db:
        old = index.graph_hash(db)
    v5 = put(store, 105, [v[4]])
    with closing(index.open_index(store, refresh=False)) as db:
        assert index.graph_hash(db) == old
    with closing(index.open_index(store)) as db:
        assert index.graph_hash(db) != old
        assert query.why(db, v5)["depth"] == 4


def test_a_record_filed_under_another_name_is_not_indexed(dag):
    store, v = dag
    moved = store / "variants" / ("0" * 64 + ".json")
    moved.write_bytes((store / "variants" / f"{v[0][7:]}.json").read_bytes())
    with closing(index.open_index(store)) as db:
        names = {n["variant"] for n in index.graph(db)["nodes"]}
    assert "sha256:" + "0" * 64 not in names and len(names) == 5
    assert len(read_folder(store)) == 6


def test_two_records_for_one_variant_keep_the_lowest_oid(tmp_path):
    rows = [{"variant": "a", "oid": oid, "signer": "s", "signed": 1, "loop": "", "parents": [],
             "evidence": []} for oid in ("o2", "o1", "o3")]  # fmt: skip
    path = tmp_path / "i.sqlite"
    assert index.write_index(path, rows, source="x") == {"variants": 1, "conflicts": 2}
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("SELECT oid FROM variants").fetchone() == ("o1",)


def test_cli_graph_why_archive_index(capsys, dag):
    store, v = dag
    where = ("--dir", str(store))
    code, out = tine(capsys, "lineage", "graph", *where)
    assert code == 0 and out.startswith("digraph lineage {")
    assert f"{json.dumps(v[4])} -> {json.dumps(v[3])};" in out
    for argv in (("graph", "--format", "json"), ("why", v[0], "--json"),
                 ("archive", "--signed", "--json"), ("index", "--rebuild", "--json")):  # fmt: skip
        code, out = tine(capsys, "lineage", *argv, *where)
        document = json.loads(out)
        assert code == 0 and _schemas.validate_output(document) == [], argv
    assert document["path"] == index.index_path(store).as_posix()
    code, _out = tine(capsys, "lineage", "why", "nope", *where)
    assert code != 0
    code, _out = tine(capsys, "lineage", "why", "sha256:" + "e" * 64, *where)
    assert code != 0
