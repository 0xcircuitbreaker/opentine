"""0.59 lineage scale: a 1e5-node synthetic archive, proven by counts, not wall time.

``why`` must touch O(depth + evidence) index rows whatever the archive size, so
the same query on a 1e3-node and a 1e5-node archive visits exactly the same
rows, and every query it issues is an index SEARCH, never a table SCAN.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest

from opentine import _lineage_index as index
from opentine import _lineage_query as query

SPINE = 40  # the queried variant's depth


def _row(variant, parents, loop="evo"):
    evidence = [("eval", f"run:{variant}-e", ""), ("judge", "judge:j", f"run:{variant}-e"),
                ("dataset", "dataset:c1", f"run:{variant}-e")]  # fmt: skip
    return {"variant": variant, "oid": f"attestation:sha256:{variant}", "signer": "s",
            "signed": 1, "loop": loop, "parents": sorted(parents),
            "evidence": evidence}  # fmt: skip


def archive(size):
    """A spine of SPINE variants plus a population with non-linear parents."""
    for n in range(SPINE):
        yield _row(f"s{n:03d}", [f"s{n - 1:03d}"] if n else [])
    for n in range(size - SPINE):
        parents = {f"s{n % SPINE:03d}"}  # every spine variant gets many children
        if n >= 2:
            parents |= {f"p{(n * 7919) % n:06d}", f"p{n // 2:06d}"}
        yield _row(f"p{n:06d}", parents)


def _build(tmp_path, size, name, rows=None):
    path = tmp_path / f"{name}.sqlite"
    index.write_index(path, rows if rows is not None else archive(size), source=name)
    return sqlite3.connect(path)


@pytest.fixture(scope="module")
def big(tmp_path_factory):
    db = _build(tmp_path_factory.mktemp("lineage-big"), 100_000, "big")
    yield db
    db.close()


def test_why_visits_the_same_rows_at_1e3_and_1e5(tmp_path, big):
    with closing(_build(tmp_path, 1_000, "small")) as small:
        a = query.why(small, f"s{SPINE - 1:03d}")
    b = query.why(big, f"s{SPINE - 1:03d}")
    assert a == b
    assert len(b["ancestors"]) == SPINE and b["depth"] == SPINE - 1
    # one node lookup, one evidence query and one edge query per ancestor
    assert b["visited"]["queries"] == 3 * SPINE
    nodes, evidence, edges = SPINE, 3 * SPINE, SPINE - 1
    assert b["visited"]["rows"] == nodes + evidence + edges


def test_why_on_a_population_member_is_bounded_by_its_ancestry(big):
    body = query.why(big, "p099959")
    ancestry = len(body["ancestors"])
    assert ancestry < 100_000 // 10  # an ancestry, not the archive
    edges = sum(
        big.execute("SELECT COUNT(*) FROM edges WHERE child = ?", (a["variant"],)).fetchone()[0]
        for a in body["ancestors"]
    )
    assert body["visited"]["queries"] == 3 * ancestry
    assert body["visited"]["rows"] == ancestry + len(body["evidence"]) + edges


def test_every_why_query_is_an_index_search(big):
    for sql in (query._NODE, "SELECT kind, ref, detail FROM evidence WHERE variant = ?",
                "SELECT parent FROM edges WHERE child = ?"):  # fmt: skip
        plan = " ".join(row[-1] for row in big.execute(f"EXPLAIN QUERY PLAN {sql}", ("s000",)))
        assert "SEARCH" in plan and "SCAN" not in plan, (sql, plan)


def test_rebuilding_1e5_from_the_records_in_any_order_gives_the_same_hash(tmp_path, big):
    rows = list(archive(100_000))
    rows.reverse()
    with closing(_build(tmp_path, 0, "again", rows)) as again:
        assert index.graph_hash(again) == index.graph_hash(big)
        counts = again.execute("SELECT COUNT(*) FROM variants").fetchone()[0]
    assert counts == 100_000


def test_archive_reports_the_population(big):
    totals = query.archive(big, loop="evo")["totals"]
    assert totals["variants"] == 100_000 and totals["roots"] == 1
    assert totals["max_parents"] == 3 and totals["multi_parent"] > 90_000
