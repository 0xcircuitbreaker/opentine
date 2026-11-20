"""0.74: transcript embeddings, seeded clustering, recall@50 and embedding contamination."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import opentine.cli as cli
from opentine import _contamination_embed, _schemas
from opentine import _transcript_cluster as tc
from opentine import _transcript_space as te
from opentine._transcript_corpus import from_files
from scripts.gen_transcript_corpus import corpus

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "data" / "transcript_corpus.jsonl"


class FakeModel:
    """A stand-in for a pinned local model: deterministic, no weights, no network."""

    name = "fake-local-model"
    dim = 8
    weights_digest = "sha256:" + "e" * 64

    def embed(self, texts):
        return [[float(len(t) % (i + 2)) + 1.0 for i in range(self.dim)] for t in texts]


class Unpinned(FakeModel):
    weights_digest = None


def _cli(capsys, *argv):
    capsys.readouterr()
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = exc.code or 0
    body = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(body) == []
    return code, body


@pytest.fixture(scope="module")
def seeded():
    texts, behaviours = from_files([CORPUS.as_posix()])
    return te.Space(texts), behaviours


def test_the_committed_corpus_is_what_the_generator_writes():
    data = "".join(json.dumps(row, sort_keys=True) + "\n" for row in corpus())
    assert CORPUS.read_bytes() == data.encode("utf-8")
    counts = {}
    for row in corpus():
        counts[row["behaviour"]] = counts.get(row["behaviour"], 0) + 1
    assert counts == {"none": 510, "reward-hacking": 30, "test-deletion": 30,
                      "sabotage-side-task": 30}  # fmt: skip


def test_seeded_behaviour_recall_at_50_is_at_least_0_9(seeded):
    space, behaviours = seeded
    result = tc.recall_at(space, behaviours, k=50, exemplars=5)
    assert set(result["behaviours"]) == {"reward-hacking", "test-deletion", "sabotage-side-task"}
    for row in result["behaviours"].values():
        assert row["relevant"] == 25
        assert row["found"] >= 23  # 23 of 25 = 0.92
    assert result["min_recall"] >= 0.9


def test_clustering_is_seeded_and_names_clusters_by_members(seeded):
    space, _ = seeded
    first, again = tc.kmeans(space, 12, seed=3), tc.kmeans(space, 12, seed=3)
    assert first == again
    members = [m for c in first["clusters"] for m in c["members"]]
    assert sorted(members) == space.ids
    for c in first["clusters"]:
        assert c["id"] == tc.cluster_id(c["members"]) and c["size"] == len(c["members"])
        assert c["exemplar"] in c["members"]
    other = tc.kmeans(space, 12, seed=4)
    assert other == tc.kmeans(space, 12, seed=4)
    assert 1 <= first["iterations"] <= tc.ITERATIONS


def test_the_backend_digest_names_the_parameters():
    assert te.backend_digest() == te.backend_digest()
    assert te.backend_digest(dim=1024) != te.backend_digest()
    assert te.backend_digest(seed=1) != te.backend_digest()
    space = te.Space({"a": "rm tests", "b": "edit code"})
    assert space.backend() == {"name": te.NAME, "dim": te.DIM, "digest": te.backend_digest(),
                               "weights_digest": None}  # fmt: skip


def test_a_model_backend_must_carry_a_weights_digest():
    assert te.load_model(None) is None and te.load_model("tfidf-hash") is None
    with pytest.raises(ValueError, match="weights_digest"):
        te.load_model("tests.test_074_transcript_cluster:Unpinned")
    with pytest.raises(ValueError, match="locally"):
        te.load_model("https://example.invalid/model")
    model = te.load_model("tests.test_074_transcript_cluster:FakeModel")
    space = te.Space({"a": "x", "b": "yy", "c": "zzz"}, model=model)
    backend = space.backend()
    assert backend["weights_digest"] == FakeModel.weights_digest and backend["dim"] == 8
    assert backend["digest"] != te.backend_digest()
    assert len(tc.similar(space, ["a"], 5)) == 2


def test_similar_excludes_exemplars_and_refuses_unknown_runs(seeded):
    space, _ = seeded
    rows = tc.similar(space, ["t0000"], 10)
    assert len(rows) == 10 and all(r["run"] != "t0000" for r in rows)
    assert [r["score"] for r in rows] == sorted((r["score"] for r in rows), reverse=True)
    with pytest.raises(KeyError):
        tc.similar(space, ["nope"], 3)


def test_cli_cluster_over_a_corpus(capsys, tmp_path):
    lines = CORPUS.read_bytes().splitlines()[:60]
    small = tmp_path / "c.jsonl"
    small.write_bytes(b"\n".join(lines) + b"\n")
    code, body = _cli(capsys, "transcripts", "cluster", "--corpus", small.as_posix(),
                      "--k", "4", "--seed", "7", "--json")  # fmt: skip
    assert code == 0 and body["k"] == 4 and body["seed"] == 7
    assert body["corpus"]["source"] == "files" and body["corpus"]["count"] == 60
    assert body["backend"]["digest"] == te.backend_digest()
    assert sum(c["size"] for c in body["clusters"]) == 60
    _, again = _cli(capsys, "transcripts", "cluster", "--corpus", small.as_posix(),
                    "--k", "4", "--seed", "7", "--json")  # fmt: skip
    assert again == body


HOLDOUT = ("The function returns the sum of the prices after the discount is applied and "
           "rounds the total to two decimal places before the invoice is printed")  # fmt: skip
PARAPHRASE = ("before the invoice is printed the total is rounded to two decimal places, and "
              "the function returns the prices sum after applying the discount")  # fmt: skip


def test_embedding_near_duplicates_catch_a_reordered_paraphrase():
    holdout = [{"id": "h1", "input": HOLDOUT}]
    corpus_rows = [("c#1", {"id": "1", "input": PARAPHRASE}),
                   ("c#2", {"id": "2", "input": "a note about the weather"})]  # fmt: skip
    from opentine import _contamination

    assert _contamination.check(holdout, corpus_rows)["ok"] is True  # shingles miss it
    found = _contamination_embed.check(holdout, corpus_rows, threshold=0.5)
    assert [n["found_in"] for n in found["near"]] == ["c#1"]
    assert found["backend_digest"].startswith("sha256:")
    with pytest.raises(ValueError):
        _contamination_embed.check(holdout, corpus_rows, threshold=0.0)


def test_cli_contamination_reports_embedding_near_duplicates(capsys, tmp_path):
    hold = tmp_path / "h.jsonl"
    hold.write_bytes((json.dumps({"id": "h1", "input": HOLDOUT}) + "\n").encode("utf-8"))
    against = tmp_path / "c.jsonl"
    against.write_bytes((json.dumps({"id": "1", "input": PARAPHRASE}) + "\n").encode("utf-8"))
    code, body = _cli(capsys, "dataset", "contamination", hold.as_posix(), "--against",
                      against.as_posix(), "--repo", tmp_path.as_posix(), "--json")  # fmt: skip
    assert code == 0 and "embedding" not in body
    code, body = _cli(capsys, "dataset", "contamination", hold.as_posix(), "--against",
                      against.as_posix(), "--embedding-threshold", "0.5",
                      "--repo", tmp_path.as_posix(), "--json")  # fmt: skip
    assert code == 1 and body["ok"] is False
    assert body["embedding"]["near"][0]["id"] == "h1"
