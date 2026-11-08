"""0.46 hybrid search: FTS5 BM25 fused with a local embedding index of redacted text."""

from __future__ import annotations

import builtins
import json
import sys
import types

import pytest

import opentine.cli as cli
from opentine._schemas import validate
from opentine.graph import Run, RunStatus, StepKind
from opentine.repository import Repo, _embed, _embed_index, _hybrid, _search_index

GHP = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

pytestmark = pytest.mark.skipif(
    not _search_index.fts5_available(), reason="sqlite3 built without FTS5"
)

#: Topic words -> axis of the fake embedder's 3-d space.
TOPICS = {"database": 0, "postgres": 0, "sql": 0, "parser": 1, "grammar": 1, "kubernetes": 2}


class FakeEmbedder:
    """Deterministic: a vector of topic-word counts. Records every text it sees."""

    name = "fake/1"
    dim = 3

    def __init__(self) -> None:
        self.seen: list[str] = []

    def embed(self, texts):
        self.seen += texts
        out = []
        for text in texts:
            vector = [0.0, 0.0, 0.0]
            for word in text.casefold().split():
                axis = TOPICS.get(word.strip(".,:"))
                if axis is not None:
                    vector[axis] += 1.0
            out.append(vector)
        return out


def _run(name: str, prompt: str) -> Run:
    run = Run(run_id=name, model_info="m-1", status=RunStatus.completed)
    run.add_step(StepKind.model, {"prompt": prompt}, {"text": "ok"})
    return run


@pytest.fixture
def repo(tmp_path):
    repo = Repo.init(tmp_path / "work")
    repo.put_run(_run("a", "tune the postgres pool"), ref="heads/a")
    repo.put_run(_run("b", "write the database migration guide"))
    repo.put_run(_run("c", "fix the parser grammar"))
    return repo


def test_rrf_fuses_and_breaks_ties_by_id():
    assert _hybrid.fuse(["x", "y"], ["y", "z"]) == ["y", "x", "z"]
    assert _hybrid.fuse(["b"], ["a"]) == ["a", "b"]
    assert _hybrid.fuse([], []) == []


def test_hybrid_finds_what_bm25_alone_misses(repo):
    _search_index.rebuild(repo)
    lexical = {result.run_id for result in repo.search("database")}
    embedder = FakeEmbedder()
    found = _hybrid.hybrid_search(repo, "database", embedder=embedder, classifier=None)
    ids = [result.run_id for result in found]
    assert len(lexical) == 1 and len(ids) == 2  # postgres is near database in the fake space
    assert set(ids) > lexical and ids[0] in lexical  # in both lists: ranked first
    again = _hybrid.hybrid_search(repo, "database", embedder=embedder, classifier=None)
    assert [result.run_id for result in again] == ids  # deterministic


def test_hybrid_builds_missing_indexes_and_only_embeds_new_runs(repo):
    embedder = FakeEmbedder()
    _hybrid.hybrid_search(repo, "parser", embedder=embedder, classifier=None)
    assert _search_index.index_path(repo).is_file() and _embed_index.index_path(repo).is_file()
    assert len(embedder.seen) == 3 + 1  # three runs, one query
    repo.put_run(_run("d", "kubernetes upgrade"))
    _hybrid.hybrid_search(repo, "kubernetes", embedder=embedder, classifier=None)
    assert len(embedder.seen) == 4 + 1 + 1


def test_only_redacted_text_is_embedded(tmp_path):
    from opentine._pii_classify import RuleClassifier

    repo = Repo.init(tmp_path / "pii")
    repo.put_run(_run("leak", f"my token {GHP} mail jane@example.com, SSN 219-09-9999"))
    embedder = FakeEmbedder()
    _hybrid.hybrid_search(repo, "x", embedder=embedder, classifier=RuleClassifier())
    joined = "\n".join(embedder.seen)
    assert GHP not in joined and "jane@example.com" not in joined and "219-09-9999" not in joined
    assert "[REDACTED:email]" in joined


def test_filters_still_apply(repo):
    found = _hybrid.hybrid_search(
        repo, "database", embedder=FakeEmbedder(), classifier=None, model="nope"
    )
    assert found == []


def test_default_hash_embedder_is_deterministic_and_normalised():
    embedder = _embed.load("hash")
    one, two = embedder.embed(["parser grammar", "parser grammar"])
    assert one == two and len(one) == embedder.dim
    assert abs(sum(value * value for value in one) - 1.0) < 1e-9
    with pytest.raises(ValueError, match="locally"):
        _embed.load("https://embed.example.invalid")


def test_pure_python_scan_matches_numpy(repo, monkeypatch):
    embedder = FakeEmbedder()
    first = _hybrid.hybrid_search(repo, "database", embedder=embedder, classifier=None)
    real_import = builtins.__import__

    def no_numpy(name, *args, **kwargs):
        if name == "numpy":
            raise ImportError("no numpy")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_numpy)
    second = _hybrid.hybrid_search(repo, "database", embedder=embedder, classifier=None)
    assert [r.run_id for r in first] == [r.run_id for r in second]


def test_cli_hybrid_json_with_a_plugged_in_embedder(repo, capsys, monkeypatch):
    module = types.ModuleType("fake_embedder_mod")
    module.Fake = FakeEmbedder
    monkeypatch.setitem(sys.modules, "fake_embedder_mod", module)
    cli.main(["repo-search", "database", "--hybrid", "--embedder", "fake_embedder_mod:Fake",
              "--repo", str(repo.worktree), "--json"])  # fmt: skip
    out = json.loads(capsys.readouterr().out)
    assert out["hybrid"] is True and out["embedder"] == "fake/1" and out["count"] == 2
    assert validate(out) == ("tine-search-results-1", [])


def test_cli_hybrid_flag_conflicts(repo):
    for argv in (["--hybrid", "--no-index"], ["--embedder", "hash"]):
        with pytest.raises(SystemExit) as info:
            cli.main(["repo-search", "x", *argv, "--repo", str(repo.worktree)])
        assert info.value.code != 0
