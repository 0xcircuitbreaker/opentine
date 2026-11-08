"""Answer ``Repo.search`` from the derived FTS5 index when it is present.

Each word of the query must occur (FTS5 implicit AND over ``unicode61``
tokens, case- and diacritic-insensitive); matches rank by BM25. An empty query
lists indexed runs newest first. There is no candidate cap: filters stream
over the ranked rows until ``limit`` results are kept. Evaluation scores are
still read from the attestation objects, for the kept rows only, so a score
written after indexing is never stale. ``None`` means "no usable index": the
caller then scans as before.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from typing import TYPE_CHECKING, Any

from opentine.repository._search_index import INDEX_FORMAT, fts5_available, index_path

if TYPE_CHECKING:
    from opentine.repository.search import SearchResult
    from opentine.repository.store import Repo

MAX_QUERY_TERMS = 64
_WORD = re.compile(r"\w+", re.UNICODE)


def fts_query(query: str) -> str:
    """A safe FTS5 MATCH expression: every word quoted, so no query syntax leaks in."""
    words = _WORD.findall(query)[:MAX_QUERY_TERMS]
    return " ".join('"' + word.replace('"', '""') + '"' for word in words)


def _open(repo: Repo) -> sqlite3.Connection | None:
    path = index_path(repo)
    if not fts5_available() or not path.is_file():
        return None
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
        row = connection.execute("SELECT value FROM meta WHERE key = 'format'").fetchone()
    except sqlite3.Error:
        return None
    if row != (INDEX_FORMAT,):
        connection.close()
        return None
    return connection


def ranked_rows(repo: Repo, query: str, *, successful_only: bool, limit: int | None = None):
    """``(run_id, status, models, cost, latency, snippet)`` rows, best first, or None."""
    expression = fts_query(query)
    if query.strip() and not expression:
        return None  # only punctuation: the scan's substring match handles it
    connection = _open(repo)
    if connection is None:
        return None
    status = " AND r.status = 'completed'" if successful_only else ""
    bound = f" LIMIT {int(limit)}" if limit else ""
    if expression:
        sql = (
            "SELECT r.run_id, r.status, r.models, r.cost, r.latency,"
            " snippet(docs, -1, '', '', '...', 32) FROM docs JOIN runs r ON r.id = docs.rowid"
            f" WHERE docs MATCH ?{status} ORDER BY bm25(docs), r.run_id{bound}"
        )
        params: tuple[Any, ...] = (expression,)
    else:
        where = status.replace(" AND", " WHERE", 1)
        sql = (
            "SELECT r.run_id, r.status, r.models, r.cost, r.latency, '' FROM runs r"
            f"{where} ORDER BY r.created_at DESC, r.run_id{bound}"
        )
        params = ()

    def rows():
        with closing(connection):
            try:
                yield from connection.execute(sql, params)
            except sqlite3.Error:
                return

    return rows()


def indexed_search(
    repo: Repo,
    query: str,
    *,
    successful_only: bool,
    min_score: float | None,
    model: str | None,
    limit: int,
    signed_only: bool,
    rows: Any = None,
) -> list[SearchResult] | None:
    """*rows* (0.46): pre-ranked rows to filter instead of the BM25 ranking (hybrid search)."""
    if rows is None:
        rows = ranked_rows(repo, query, successful_only=successful_only)
    if rows is None:
        return None
    from opentine.repository._associations import associated_map, association_indexes
    from opentine.repository._search_scores import best_score, collect_scores
    from opentine.repository.search import SearchResult, _finite

    indexes = association_indexes(repo)

    def payload_of(oid: str) -> dict[str, Any] | None:
        try:
            return repo.get(oid).payload()
        except (KeyError, OSError, ValueError):
            return None

    results: list[SearchResult] = []
    for run_id, status, models_json, cost, latency, snippet in rows:
        models = tuple(json.loads(models_json))
        if model and not any(model.casefold() in name.casefold() for name in models):
            continue
        found = associated_map(repo, [run_id], 100_000, indexes=indexes).get(run_id) or []
        attestations = [oid for oid in found if oid.startswith("attestation:")]
        scores = collect_scores(attestations, payload_of, _finite)
        score, signed = best_score(scores.get(run_id) or [], signed_only=signed_only)
        if min_score is not None and (score is None or score < min_score):
            continue
        text = snippet[:240]
        results.append(SearchResult(run_id, status, score, cost, latency, models, text, signed))
        if len(results) >= limit:
            rows.close()
            break
    return results
