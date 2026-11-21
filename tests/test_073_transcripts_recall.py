"""0.74 (release 0.73.0) acceptance: seeded-behaviour recall and contamination near-duplicates.

The committed synthetic corpus (:mod:`tests.transcript_corpus`, pinned by its
digest) plants eight behaviours in 20 runs each among 400. Querying with every
seeded run, the other members of its behaviour found in the top 50 must be at
least 90% on average (counts, not timings). A smaller corpus goes through a
real repository end to end. Embedding near-duplicates feed ``tine dataset
contamination``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _contamination_embed, _schemas
from opentine import _transcript_ann as ann
from opentine import _transcript_embed as te
from opentine import _transcript_index as ti
from opentine.repository import Repo
from tests import transcript_corpus as tc
from tests.query_helpers import tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
CORPUS_DIGEST = "5e0d5e7df768ef1d7e1d8a50259447f6328ae50069902c21f10998f98a681053"


def _recall(index: ann.Index, labels: dict[str, str | None], k: int = 50) -> tuple[int, int]:
    found = total = 0
    for name, label in sorted(labels.items()):
        if label is None:
            continue
        others = {n for n, lab in labels.items() if lab == label} - {name}
        vector = index.vectors[index.runs.index(name)]
        hits = {h["run"] for h in index.search(vector, k, exclude=name)["hits"]}
        found += len(hits & others)
        total += len(others)
    return found, total


def test_seeded_behaviour_recall_at_top_50_is_at_least_0_9():
    rows = tc.specs()
    assert tc.digest(rows) == CORPUS_DIGEST
    backend = te.HashBackend()
    vectors = backend.embed([tc.render(r) for r in rows])
    index = ann.Index((r["name"], v, None) for r, v in zip(rows, vectors, strict=True))
    found, total = _recall(index, {r["name"]: r["behaviour"] for r in rows})
    assert total == 8 * 20 * 19
    assert found * 10 >= total * 9, (found, total)


def test_recall_through_a_repository_and_the_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    rows = tc.specs(n=48, per_behaviour=4, seed=11)
    labels = tc.write(repo, rows)
    built = ti.build(repo, workers=1)
    assert built["runs"] == 48 and built["embedded"] == 48
    index, _, _ = ti.load(ti.index_path(repo.path))
    found, total = _recall(index, labels, k=10)
    assert total == 8 * 4 * 3 and found * 10 >= total * 9, (found, total)
    query = next(oid for oid, label in sorted(labels.items()) if label == "exfil")
    code, body = tine(capsys, "transcripts", "similar", query, "-k", "3", "--repo", "r")
    assert code == 0, body
    _schemas.validate(body, "tine-cli-transcripts-1")
    assert labels[body["hits"][0]["run"]] == "exfil" and len(body["hits"]) == 3


def _jsonl(path: Path, rows: list[tuple[str, str]]) -> str:
    path.write_bytes(b"".join(json.dumps({"id": i, "input": t}).encode() + b"\n" for i, t in rows))
    return path.as_posix()


ITEM = ("the committee reviewed every submitted proposal for the regional water project and "
        "found that the northern district had the most urgent need")  # fmt: skip
REORDERED = ("for the regional water project the committee found the most urgent need in the "
             "northern district after it reviewed every proposal submitted")  # fmt: skip
OTHER = "a recipe for bread needs flour water salt and yeast mixed and kneaded until smooth"


def test_embedding_near_duplicates_feed_the_contamination_check(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    holdout = _jsonl(tmp_path / "h.jsonl", [("h1", ITEM), ("h2", OTHER)])
    corpus = _jsonl(tmp_path / "c.jsonl", [("c1", REORDERED), ("c2", "unrelated words here")])
    code, plain = tine(capsys, "dataset", "contamination", holdout, "--against", corpus)
    assert code == 0 and plain["ok"] is True and "embedding" not in plain
    code, body = tine(capsys, "dataset", "contamination", holdout, "--against", corpus,
                      "--embedding-threshold", "0.6")  # fmt: skip
    assert code == 1, body
    _schemas.validate(body, "tine-cli-canary-1")
    assert body["near"] == [] and body["counts"]["embedding"] == 1
    emb = body["embedding"]
    assert emb["backend_digest"] == te.backend_digest(te.HashBackend()) and emb["threshold"] == 0.6
    assert [(n["id"], n["found_in"].endswith("#c1")) for n in emb["near"]] == [("h1", True)]


def test_an_item_already_reported_is_not_repeated_by_the_embedding_check():
    corpus = [("c#1", {"input": ITEM})]
    result = _contamination_embed.check([{"id": "h1", "input": ITEM}], corpus, threshold=0.9,
                                        skip=frozenset({"h1"}))  # fmt: skip
    assert result["near"] == []
    with pytest.raises(ValueError):
        _contamination_embed.check([], corpus, threshold=0.0)
