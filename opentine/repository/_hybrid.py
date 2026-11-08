"""Hybrid search: FTS5 BM25 fused with local embeddings (0.46, ``repo-search --hybrid``).

Two ranked lists of runs -- the FTS5 BM25 ranking of :mod:`._search_query` and
the cosine ranking of :mod:`._embed_index` -- are fused by reciprocal rank
fusion: a run's fused score is ``sum(1 / (RRF_K + rank))`` over the lists it
appears in (ranks from 1), ties broken by run id. The fused rows then go
through the same filters as an indexed search (status, model, score, signed),
so ``--hybrid`` changes the order and recall of results, never what a filter
admits.

Hybrid search needs the FTS5 index (it is written when missing) and embeds, at
query time, any indexed run the embedding index does not hold yet.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from typing import TYPE_CHECKING, Any

from opentine.repository import _embed_index
from opentine.repository._search_index import fts5_available, index_path, rebuild
from opentine.repository._search_query import indexed_search, ranked_rows

if TYPE_CHECKING:
    from opentine.repository.search import SearchResult
    from opentine.repository.store import Repo

RRF_K = 60
CANDIDATES = 200


def fuse(*rankings: list[str], k: int = RRF_K) -> list[str]:
    """Reciprocal rank fusion of ranked id lists; best first, ties by id."""
    scores: dict[str, float] = {}
    for ranking in rankings:
        for rank, item in enumerate(dict.fromkeys(ranking), start=1):
            scores[item] = scores.get(item, 0.0) + 1.0 / (k + rank)
    return sorted(scores, key=lambda item: (-scores[item], item))


def _runs(repo: Repo, successful_only: bool) -> dict[str, tuple[Any, ...]]:
    status = " WHERE status = 'completed'" if successful_only else ""
    path = index_path(repo)
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)) as connection:
        rows = connection.execute(
            f"SELECT run_id, status, models, cost, latency FROM runs{status}"
        ).fetchall()
    return {row[0]: row for row in rows}


def hybrid_search(
    repo: Repo,
    query: str,
    *,
    embedder: Any,
    classifier: Any,
    successful_only: bool = True,
    min_score: float | None = None,
    model: str | None = None,
    limit: int = 20,
    signed_only: bool = False,
) -> list[SearchResult]:
    if not fts5_available():
        raise RuntimeError("hybrid search needs sqlite3 with FTS5")
    if not index_path(repo).is_file():
        rebuild(repo)
    runs = _runs(repo, successful_only)
    _embed_index.refresh(repo, sorted(runs), embedder, classifier)
    lexical: list[str] = []
    snippets: dict[str, str] = {}
    if query.strip():
        rows = ranked_rows(repo, query, successful_only=successful_only, limit=CANDIDATES)
        for row in rows or ():
            lexical.append(row[0])
            snippets[row[0]] = row[5]
        semantic = _embed_index.nearest(repo, query, embedder, set(runs), CANDIDATES)
        order = fuse(lexical, semantic)
    else:
        order = sorted(runs)
    fused = (runs[run_id] + (snippets.get(run_id, ""),) for run_id in order if run_id in runs)
    filters = dict(min_score=min_score, model=model, limit=limit, signed_only=signed_only)
    found = indexed_search(repo, query, successful_only=successful_only, rows=fused, **filters)
    return found or []


__all__ = ["CANDIDATES", "RRF_K", "fuse", "hybrid_search"]
