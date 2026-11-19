"""JSON Schema for ``tine query ... --json`` (0.65): SQL over the derived index.

The index itself is a derived, non-authoritative file, not an object kind
(docs/QUERY.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, OBJ, STR, closed, doc, opt, strs

_HEAD = {"schema": {"const": "tine-cli-query/1"}, "authority": {"const": "non-authoritative"}}
_STATUS = {"enum": ["verified", "unverified", "failed"]}
_CHECK = closed(
    ["oid", "status", "reason", "signer", "roles"],
    {"oid": opt(STR), "status": _STATUS, "reason": STR, "signer": opt(STR), "roles": strs()},
)
_COUNTS = {"type": "object", "additionalProperties": INT}
_SHAPES = [
    closed(["command", "schema", "authority", "stale", "stale_reasons", "columns", "rows",
            "truncated", "verification"], {
        **_HEAD, "command": {"const": "query"}, "stale": BOOL, "stale_reasons": strs(),
        "columns": strs(), "rows": {"type": "array", "items": OBJ}, "truncated": BOOL,
        "verification": opt(closed(["counts", "rows"], {
            "counts": closed(["verified", "unverified", "failed"], {
                "verified": INT, "unverified": INT, "failed": INT}),
            "rows": {"type": "array", "items": _CHECK}}))}),
    closed(["command", "schema", "authority", "index", "rebuilt", "exists", "stale", "reasons",
            "counts", "evals"], {
        **_HEAD, "command": {"const": "query index"}, "index": STR, "rebuilt": BOOL,
        "exists": BOOL, "stale": BOOL, "reasons": strs(), "counts": opt(_COUNTS),
        "evals": strs()}),
]  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-query-1": doc("tine-cli-query-1", "tine query ... --json",
        "Read-only SQL over the derived query index (`.tine/query/index.sqlite`). The index "
        "is non-authoritative: every row carries the oid it was read from, and `--verify` "
        "re-checks each returned row's object (verified, unverified or failed). "
        "`query index` reports or rebuilds the index and says whether it is stale.",
        {"anyOf": _SHAPES}),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {"query": "tine-cli-query-1", "query index": "tine-cli-query-1"}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
