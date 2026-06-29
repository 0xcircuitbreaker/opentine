"""Run tags + index/search coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Run, StepKind
from opentine.core import RunStatus
from opentine.index import QueryError, RunIndex, parse_query


def _run(run_id: str, *, model="m", tags=(), cost=0.0, text="hello", created_at=1_700_000_000.0):
    run = Run(id=run_id, model_info=model, tags=list(tags), created_at=created_at)
    run.add_step(StepKind.done, {"text": text}, cost=cost)
    run.status = RunStatus.completed
    return run


# --- Run.tags ---------------------------------------------------------------


def test_tag_normalization_dedupe_sort():
    run = Run(id="x", tags=["  Prod ", "prod", "B", "a"])
    assert run.tags == ["a", "b", "prod"]


def test_add_remove_has_tag():
    run = Run(id="x")
    assert run.add_tag("Prod") is True
    assert run.add_tag("prod") is False  # already present (normalized)
    assert run.has_tag("PROD") is True
    assert run.tags == ["prod"]
    assert run.remove_tag("prod") is True
    assert run.remove_tag("prod") is False
    assert run.tags == []


def test_tags_emitted_only_when_non_empty(tmp_path: Path):
    run = Run(id="x")
    run.add_step(StepKind.done, {"text": "hi"})
    p = run.save(tmp_path / "a.tine")
    assert "tags" not in json.loads(p.read_text())["metadata"]
    run.add_tag("prod")
    run.save(p)
    assert json.loads(p.read_text())["metadata"]["tags"] == ["prod"]


def test_retag_preserves_integrity_digest(tmp_path: Path):
    run = Run(id="x")
    run.add_step(StepKind.done, {"text": "hi"})
    p = run.save(tmp_path / "a.tine")
    digest1 = json.loads(p.read_text())["metadata"]["integrity"]["digest"]

    loaded = Run.load(p)
    loaded.add_tag("prod")
    loaded.save(p)
    digest2 = json.loads(p.read_text())["metadata"]["integrity"]["digest"]

    # Tags live outside the digest boundary, so re-tagging never changes it.
    assert digest1 == digest2
    assert Run.verify_integrity(p).ok
    assert Run.load(p).tags == ["prod"]


def test_tag_value_with_secret_word_is_not_redacted(tmp_path: Path):
    run = Run(id="x", tags=["api-key-rotation"])
    run.add_step(StepKind.done, {"text": "hi"})
    p = run.save(tmp_path / "a.tine")
    # "api-key-rotation" is a tag *value*, not a dict key, so redaction leaves it.
    assert json.loads(p.read_text())["metadata"]["tags"] == ["api-key-rotation"]


def test_fork_drops_tags():
    run = Run(id="orig", tags=["keep-me"])
    run.add_step(StepKind.think, {"text": "x"})
    forked = run.fork(run.steps[0].id)
    assert forked.tags == []


def test_v1_loads_with_empty_tags_and_roundtrips(tmp_path: Path):
    src = Path(__file__).parent / "fixtures" / "golden_v1.tine"
    run = Run.load(src)
    assert run.tags == []
    out = tmp_path / "rt.tine"
    run.save(out)
    assert "tags" not in json.loads(out.read_text())["metadata"]


# --- query DSL --------------------------------------------------------------


def test_unknown_prefix_is_free_text():
    q = parse_query("http://example.com tag:prod foo:bar hello")
    assert "http://example.com" in q.text
    assert "foo:bar" in q.text
    assert "hello" in q.text
    assert q.tags == ["prod"]


def test_cost_and_date_predicates():
    q = parse_query("cost:>0.5 after:2020-01-01 model:gpt status:failed")
    assert q.cost_min == 0.5
    assert q.model == "gpt"
    assert q.status == "failed"
    assert q.after is not None


def test_malformed_query_raises():
    with pytest.raises(QueryError):
        parse_query('unbalanced "quote')


# --- index ------------------------------------------------------------------


def test_index_search_by_tag_model_cost_text(tmp_path: Path):
    _run("alpha", model="gpt-4o", tags=["prod"], cost=0.5, text="deploy the service").save(
        tmp_path / "alpha.tine"
    )
    _run("beta", model="claude", tags=["dev"], cost=0.01, text="fix the bug").save(
        tmp_path / "beta.tine"
    )

    index = RunIndex.open(tmp_path)
    assert {e.run_id for e in index.search("tag:prod")} == {"alpha"}
    assert {e.run_id for e in index.search("model:claude")} == {"beta"}
    assert {e.run_id for e in index.search("cost:>0.1")} == {"alpha"}
    assert {e.run_id for e in index.search("deploy")} == {"alpha"}
    assert {e.run_id for e in index.search("")} == {"alpha", "beta"}


def test_index_incremental_and_prune(tmp_path: Path):
    a = _run("alpha").save(tmp_path / "alpha.tine")
    index = RunIndex.open(tmp_path).sync()
    assert set(index.entries) == {"alpha.tine"}

    _run("beta").save(tmp_path / "beta.tine")
    index.sync()
    assert set(index.entries) == {"alpha.tine", "beta.tine"}

    Path(a).unlink()
    index.sync()
    assert set(index.entries) == {"beta.tine"}


def test_index_skips_unreadable_file(tmp_path: Path):
    _run("good").save(tmp_path / "good.tine")
    (tmp_path / "broken.tine").write_text("{ not json", encoding="utf-8")
    index = RunIndex.open(tmp_path).sync()
    assert index.entries["broken.tine"].unreadable is True
    assert index.entries["good.tine"].unreadable is False
    # unreadable entries never match a query
    assert {e.run_id for e in index.search("")} == {"good"}


def test_index_rebuilds_on_format_version_bump(tmp_path: Path):
    _run("alpha").save(tmp_path / "alpha.tine")
    # Simulate an index built by an older format version.
    stale = {"index_version": 1, "covered_format_version": 1, "entries": {}}
    (tmp_path / "index.json").write_text(json.dumps(stale), encoding="utf-8")

    index = RunIndex.open(tmp_path)
    assert index.entries == {}  # discarded as stale on load
    index.sync()
    assert "alpha.tine" in index.entries
    assert index.entries["alpha.tine"].run_id == "alpha"


def test_lookup_by_run_id_prefix(tmp_path: Path):
    _run("abcdef123").save(tmp_path / "custom-name.tine")
    index = RunIndex.open(tmp_path).sync()
    entry = index.lookup("abcdef")
    assert entry is not None and entry.file == "custom-name.tine"
