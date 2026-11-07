"""0.44: the derived FTS5 BM25 search index at ``.tine/index/search.sqlite``."""

from __future__ import annotations

import json
import sqlite3

import pytest

import opentine.cli as cli
from opentine.graph import Run, RunStatus, StepKind
from opentine.repository import Repo, _search_index, _search_query

GHP = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

pytestmark = pytest.mark.skipif(
    not _search_index.fts5_available(), reason="sqlite3 built without FTS5"
)


def _run(name: str, prompt: str, *, tool: str = "Bash", path: str = "src/app.py") -> Run:
    run = Run(run_id=name, model_info="claude-opus-5-5", status=RunStatus.completed)
    run.add_step(StepKind.model, {"prompt": prompt}, {"text": f"answer about {prompt}"})
    run.add_step(StepKind.tool, {"name": tool, "arguments": {"file_path": path}})
    return run


@pytest.fixture
def repo(tmp_path):
    repo = Repo.init(tmp_path / "work")
    repo.put_run(_run("alpha", "refactor the parser module"), ref="heads/alpha")
    repo.put_run(_run("beta", "write docs for the parser", tool="Write", path="docs/guide.md"))
    repo.put_run(_run("gamma", "tune the database pool"))
    return repo


def test_index_answers_like_the_scan_and_ranks_by_bm25(repo):
    scanned = {result.run_id for result in repo.search("parser")}
    assert not _search_index.index_path(repo).exists()
    assert _search_index.rebuild(repo) == 3
    indexed = repo.search("parser")
    assert {result.run_id for result in indexed} == scanned and len(scanned) == 2
    assert all(result.matched_text for result in indexed)
    assert repo.search("parser", use_index=False)  # the scan stays reachable


def test_terms_are_anded_and_cover_tools_paths_and_metadata(repo):
    _search_index.rebuild(repo)
    assert len(repo.search("parser docs")) == 1
    assert len(repo.search("guide.md")) == 1  # a file path from tool arguments
    assert len(repo.search("Write")) >= 1  # a tool name
    assert len(repo.search("claude opus")) == 3  # run metadata (model)
    assert repo.search("nonexistentword") == []


def test_put_run_and_import_update_an_existing_index(repo, tmp_path):
    _search_index.rebuild(repo)
    repo.put_run(_run("delta", "migrate the kubernetes cluster"))
    assert len(repo.search("kubernetes")) == 1
    other = Repo.init(tmp_path / "other")
    other.put_run(_run("epsilon", "observability dashboards"), ref="heads/main")
    from opentine.repository.pack import create_pack, reachable

    tip = other.read_ref("heads/main")
    repo.import_pack(create_pack(other, reachable(other, [tip])))
    assert len(repo.search("observability")) == 1


def test_no_index_is_created_implicitly(tmp_path):
    repo = Repo.init(tmp_path / "plain")
    repo.put_run(_run("alpha", "anything"))
    assert not _search_index.index_path(repo).exists()


def test_only_stored_redacted_text_reaches_the_index(tmp_path):
    repo = Repo.init(tmp_path / "secret")
    repo.put_run(_run("leak", f"export GITHUB_TOKEN={GHP}"))
    _search_index.rebuild(repo)
    assert GHP.encode() not in _search_index.index_path(repo).read_bytes()


def test_a_failed_incremental_update_drops_the_index(repo, monkeypatch):
    _search_index.rebuild(repo)

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(_search_index, "_upsert", boom)
    repo.put_run(_run("zeta", "lost update"))
    assert not _search_index.index_path(repo).exists()
    monkeypatch.undo()
    assert len(repo.search("lost update")) == 1  # the scan answers instead


def test_query_syntax_is_quoted_never_interpreted(repo):
    _search_index.rebuild(repo)
    assert _search_query.fts_query('a" OR b NEAR(') == '"a" "OR" "b" "NEAR"'
    assert repo.search('parser" OR "*') == []
    assert repo.search("((") == []  # punctuation only: the scan's substring match


def test_without_fts5_search_scans_and_rebuild_refuses(repo, monkeypatch):
    monkeypatch.setattr(_search_index, "_FTS5", False)
    with pytest.raises(RuntimeError, match="FTS5"):
        _search_index.rebuild(repo)
    assert len(repo.search("parser")) == 2


def test_an_unknown_index_format_is_ignored(repo):
    _search_index.rebuild(repo)
    with sqlite3.connect(_search_index.index_path(repo)) as connection:
        connection.execute("UPDATE meta SET value = 'future/9' WHERE key = 'format'")
    assert len(repo.search("parser")) == 2


class _FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, *args, **kwargs):
        return lambda function: self.tools.setdefault(function.__name__, function)

    def resource(self, *args, **kwargs):
        return lambda function: function


def test_mcp_recall_is_read_only_bounded_and_index_only(repo):
    from opentine._mcp_readonly import READ_ONLY_TOOLS
    from opentine.mcp_repository import register_repository_tools

    assert "recall" in READ_ONLY_TOOLS
    mcp = _FakeMCP()
    register_repository_tools(mcp, str(repo.worktree))
    recall = mcp.tools["recall"]
    missing = recall("parser")
    assert missing["indexed"] is False and missing["results"] == []
    assert not _search_index.index_path(repo).exists()  # recall never builds one
    _search_index.rebuild(repo)
    found = recall("parser", limit=1)
    assert found["indexed"] is True and len(found["results"]) == 1
    row = found["results"][0]
    assert set(row) == {"run_id", "status", "models", "snippet"}
    assert len(row["snippet"]) <= 240
    for bad in ({"query": ""}, {"query": "x", "limit": 51}, {"query": "x" * 5000}):
        with pytest.raises(ValueError):
            recall(**bad)


def test_cli_rebuild_and_search(repo, capsys):
    cli.main(["repo-search", "parser", "--rebuild-index", "--repo", str(repo.worktree), "--json"])
    captured = capsys.readouterr()
    assert "indexed 3 runs" in captured.err
    assert json.loads(captured.out)["count"] == 2
