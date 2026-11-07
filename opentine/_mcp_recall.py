"""0.44: the read-only MCP ``recall`` tool over the derived search index.

``recall(query, limit)`` asks ``.tine/index/search.sqlite`` (FTS5, BM25) which
runs mention the query's words and returns at most ``MAX_RECALL_RESULTS`` short
rows: run id, status, models and a snippet of at most ``MAX_RECALL_SNIPPET``
characters. It never scans the object store and never writes: with no index it
says so (``indexed: false``) and names the command that builds one. The text it
returns is recorded run content -- untrusted, like every other read tool's.
"""

from __future__ import annotations

import json
from typing import Any

from opentine.repository._search_query import ranked_rows

MAX_RECALL_RESULTS = 50
MAX_RECALL_SNIPPET = 240
MAX_RECALL_QUERY_CHARS = 4096


def recall_index(repo: Any, query: str, limit: int = 10) -> dict[str, Any]:
    if not isinstance(query, str) or not query.strip():
        raise ValueError("recall needs a non-empty query")
    if len(query) > MAX_RECALL_QUERY_CHARS:
        raise ValueError(f"recall query exceeds {MAX_RECALL_QUERY_CHARS} characters")
    if type(limit) is not int or not 1 <= limit <= MAX_RECALL_RESULTS:
        raise ValueError(f"recall limit must be between 1 and {MAX_RECALL_RESULTS}")
    rows = ranked_rows(repo, query, successful_only=False, limit=limit)
    if rows is None:
        return {
            "indexed": False,
            "query": query,
            "results": [],
            "hint": "no search index: run `tine repo-search --rebuild-index`",
        }
    results = [
        {
            "run_id": run_id,
            "status": status,
            "models": json.loads(models)[:16],
            "snippet": snippet[:MAX_RECALL_SNIPPET],
        }
        for run_id, status, models, _cost, _latency, snippet in rows
    ]
    return {"indexed": True, "query": query, "results": results}


def register_recall(mcp: Any, repo: Any, visible: Any) -> None:
    @mcp.tool()
    def recall(query: str, limit: int = 10) -> dict[str, Any]:
        """Recall runs whose stored prompts, completions, tools or paths mention
        every word of ``query``, best BM25 match first (read-only, at most 50)."""
        return visible(recall_index(repo, query, limit))
