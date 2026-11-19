"""0.65 ``tine query``: lineage variants and edges come from the lineage folder."""

from __future__ import annotations

import pytest

from opentine._lineage import record
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.lineage_helpers import RECORDER, art
from tests.promote_helpers import AT, RUN_A, RUN_B, key
from tests.query_helpers import tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


@pytest.fixture
def lineage(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    store = repo.path / "lineage"
    root = record(key(RECORDER), run=RUN_A, artifacts=art(0), store=store, at=AT)["variant"]
    child = record(key(RECORDER), run=RUN_B, artifacts=art(1), store=store, parents=[root],
                   at=AT)["variant"]  # fmt: skip
    return {"store": store, "root": root, "child": child}


def test_variants_and_edges_are_indexed_with_their_record_oid(capsys, lineage):
    code, body = tine(capsys, "query", "SELECT e.oid, e.child, e.parent, v.signed FROM "
                      "lineage_edges e JOIN lineage_variants v ON v.oid = e.oid",
                      "--verify", "--repo", "r")  # fmt: skip
    assert code == 0, body
    assert [(r["child"], r["parent"], r["signed"]) for r in body["rows"]] == [
        (lineage["child"], lineage["root"], 1)
    ]
    check = body["verification"]["rows"][0]
    # signed and intact, but the loop's key holds no pinned role
    assert check["status"] == "unverified" and check["reason"] == "the signer holds no pinned role"


def test_an_edited_lineage_record_fails_and_makes_the_index_stale(capsys, lineage):
    code, body = tine(capsys, "query", "SELECT oid FROM lineage_variants", "--repo", "r")
    assert code == 0 and len(body["rows"]) == 2
    path = lineage["store"] / "variants" / f"{lineage['child'][7:]}.json"
    path.write_bytes(path.read_bytes().replace(b'"selector": ""', b'"selector": "edited"'))
    code, body = tine(capsys, "query", "SELECT oid, variant FROM lineage_variants", "--verify",
                      "--repo", "r")  # fmt: skip
    assert code == 1
    assert body["stale"] is True and body["stale_reasons"] == ["the lineage folder changed"]
    failed = [c for c in body["verification"]["rows"] if c["status"] == "failed"]
    assert [c["reason"] for c in failed] == ["the lineage record changed"]
