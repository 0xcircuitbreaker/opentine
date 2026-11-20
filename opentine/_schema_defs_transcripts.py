"""JSON Schema for ``tine transcripts index|search|similar --json`` (0.74, release 0.73.0).

The transcript index is a derived, non-authoritative file, not an object kind
(docs/TRANSCRIPTS.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, NUM, OBJ, STR, closed, doc, opt, strs

_HEAD = {"schema": {"const": "tine-cli-transcripts/1"},
         "authority": {"const": "non-authoritative"}}  # fmt: skip
_CAPS = closed(["step_bytes", "max_bytes"], {"step_bytes": INT, "max_bytes": INT})
_COUNTS = closed(["runs", "embedded", "reused", "truncated"],
                 {"runs": INT, "embedded": INT, "reused": INT, "truncated": INT})  # fmt: skip
_HIT = closed(["run", "score", "steps", "bytes", "truncated", "text_sha256"], {
    "run": STR, "score": NUM, "steps": INT, "bytes": INT, "truncated": BOOL,
    "text_sha256": STR})  # fmt: skip
_QUERY = {"anyOf": [closed(["text_sha256"], {"text_sha256": STR}), closed(["run"], {"run": STR})]}
_SHAPES = [
    closed(["command", "schema", "authority", "index", "rebuilt", "exists", "stale", "reasons",
            "backend", "backend_digest", "caps", "counts", "disagreeing"], {
        **_HEAD, "command": {"const": "transcripts index"}, "index": STR, "rebuilt": BOOL,
        "exists": BOOL, "stale": BOOL, "reasons": strs(), "backend": OBJ, "backend_digest": FPR,
        "caps": _CAPS, "counts": opt(_COUNTS), "disagreeing": opt(strs())}),
    closed(["command", "schema", "authority", "stale", "stale_reasons", "backend_digest",
            "query", "k", "method", "candidates", "indexed", "hits"], {
        **_HEAD, "command": {"enum": ["transcripts search", "transcripts similar"]},
        "stale": BOOL, "stale_reasons": strs(), "backend_digest": FPR, "query": _QUERY,
        "k": INT, "method": {"enum": ["exact", "lsh", "exact-fallback"]}, "candidates": INT,
        "indexed": INT, "hits": {"type": "array", "items": _HIT}}),
]  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-transcripts-1": doc("tine-cli-transcripts-1",
        "tine transcripts index|search|similar --json",
        "Embedding search over run transcripts through a derived, non-authoritative index "
        "(`.tine/transcripts/index.sqlite`). `index` reports or rebuilds it and names the "
        "embedding backend by its digest; `search` and `similar` return the nearest runs by "
        "cosine similarity, with the search method (exact, lsh, exact-fallback) and whether "
        "the index is stale.",
        {"anyOf": _SHAPES}),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    "transcripts index": "tine-cli-transcripts-1",
    "transcripts search": "tine-cli-transcripts-1",
    "transcripts similar": "tine-cli-transcripts-1",
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
