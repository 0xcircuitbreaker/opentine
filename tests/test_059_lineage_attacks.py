"""0.59 lineage graph half under attack: a loop laundering a self-modification."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing

import pytest

from opentine import _lineage_index as index
from opentine import _lineage_query as query
from opentine import _schemas
from opentine._lineage import read_folder
from opentine._lineage_check import _loads
from opentine._lineage_claim import rows as claim_rows

from .test_059_lineage_graph import put, tine

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


@pytest.fixture
def chain(tmp_path):
    store = tmp_path / "lineage"
    v0 = put(store, 200)
    v1 = put(store, 201, [v0])
    return store, v0, v1


def _load(store):
    files = read_folder(store)
    by_oid = {}
    for path, raw in files.items():
        if path.startswith("variants/"):
            import hashlib

            by_oid["sha256:" + hashlib.sha256(raw).hexdigest()] = raw
    return lambda oid: claim_rows(oid, _loads(by_oid[oid]), files) if oid in by_oid else None


def test_a_copied_signature_block_is_not_reported_as_signed(chain):
    store, v0, v1 = chain
    v2 = put(store, 202, [v1])
    path = store / "variants" / f"{v2[7:]}.json"
    payload = json.loads(path.read_bytes())
    donor = json.loads((store / "variants" / f"{v0[7:]}.json").read_bytes())
    payload["signature"] = donor["signature"]
    path.write_bytes(json.dumps(payload, sort_keys=True).encode())
    with closing(index.open_index(store)) as db:
        signed = {a["variant"]: a["signed"] for a in query.why(db, v2)["ancestors"]}
    assert signed == {v2: False, v1: True, v0: True}


def test_a_fake_parent_cycle_is_reported_and_why_terminates(tmp_path):
    from opentine._lineage import variant_id
    from tests.lineage_helpers import art

    store = tmp_path / "lineage"
    a, b = variant_id(art(301)), variant_id(art(302))
    put(store, 301, [b])
    put(store, 302, [a])
    with closing(index.open_index(store)) as db:
        assert index.graph(db)["cyclic"] == sorted([a, b])
        assert {x["variant"] for x in query.why(db, a)["ancestors"]} == {a, b}


POISON = [
    "DELETE FROM evidence WHERE variant = :v1 AND kind = 'mutation'",
    "UPDATE evidence SET ref = 'friendly' WHERE kind = 'loop' AND variant = :v0",
    "UPDATE variants SET signed = 1 WHERE variant = :vx",
    "DELETE FROM edges WHERE child = :v1",
]


@pytest.mark.parametrize("sql", POISON)
def test_a_poisoned_index_does_not_make_why_lie(capsys, chain, sql):
    store, v0, v1 = chain
    vx = put(store, 203, [v1], signed=False)
    with closing(index.open_index(store)) as db:
        honest = query.why(db, vx)
        db.execute(sql, {"v0": v0, "v1": v1, "vx": vx})
        db.commit()
    with closing(index.open_index(store)) as db:  # the folder is unchanged: not stale
        with pytest.raises(query.IndexMismatch):
            query.why(db, vx, load=_load(store))
    code, out = tine(capsys, "lineage", "why", vx, "--json", "--dir", str(store))
    body = json.loads(out)
    assert body["rebuilt"] is True and _schemas.validate_output(body) == []
    assert body["evidence"] == honest["evidence"] and body["ancestors"] == honest["ancestors"]
    # the check, not the index, decides: vx is unsigned and its parents name no eval
    assert code == 1 and body["ok"] is False
    assert {f["code"] for f in body["findings"]} >= {"lineage.record-invalid"}


def test_a_huge_ancestry_is_capped_and_marked_truncated(tmp_path):
    records = [{"variant": f"n{i}", "oid": f"o{i}", "signer": "", "signed": 0, "loop": "",
                "evidence": [], "parents": [f"n{j}" for j in range(max(0, i - 3), i)]}
               for i in range(400)]  # fmt: skip
    path = tmp_path / "i.sqlite"
    index.write_index(path, records, source="x")
    with closing(sqlite3.connect(path)) as db:
        body = query.why(db, "n399", max_nodes=50)
    assert body["truncated"] is True and len(body["ancestors"]) == 50
    assert body["visited"]["queries"] == 3 * 50
