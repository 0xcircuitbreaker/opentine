"""JSON Schemas for 0.48 "integrate everywhere": review findings and the code map.

``opentine-review-finding-1`` is one signed ``opentine.review-finding``
(SPEC 4.25); ``tine-graph-1`` is the ``--json`` output of ``tine code-graph``
(``tine-graph/1``, also the MCP ``code_graph`` tool's answer). The schemas
check shape; the signature is the verifier's (``opentine._review_finding``).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, SIG, STR, closed, doc, open_, opt

_ID: dict[str, Any] = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"}
_WHEN: dict[str, Any] = {
    "type": "string",
    "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
}
_PATH: dict[str, Any] = {"type": "string", "minLength": 1, "maxLength": 1024}
_SYMBOL = closed(["name", "kind", "line", "parent"], {
    "name": STR, "kind": {"enum": ["class", "function", "method", "type"]},
    "line": {"type": "integer", "minimum": 1}, "parent": opt(STR)})  # fmt: skip
_FILE = closed(["path", "language", "backend", "symbols", "imports"], {
    "path": _PATH, "language": STR, "backend": {"enum": ["tree-sitter", "regex"]},
    "symbols": {"type": "array", "items": _SYMBOL},
    "imports": {"type": "array", "items": STR}})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-review-finding-1": doc("opentine-review-finding-1",
        "opentine.review-finding (finding_version 1)",
        "One reviewer's finding on a Review (SPEC 4.25), as `tine review run` signs it: the "
        "review and finding ids, severity, an optional repository-relative path and 1-based "
        "line, the message, the reviewer (fleet member) and its run. `signature` is an "
        "Ed25519 tine-sig/3 block over `opentine.review-finding.v1:` + JCS({body, header}).",
        closed(["kind", "finding_version", "review_id", "finding_id", "severity", "path",
                "line", "message", "reviewer", "run", "created_at", "signature"], {
            "kind": {"const": "opentine.review-finding"}, "finding_version": {"const": 1},
            "review_id": _ID, "finding_id": _ID,
            "severity": {"enum": ["info", "low", "medium", "high", "critical"]},
            "path": opt(_PATH), "line": opt({"type": "integer", "minimum": 1}),
            "message": {"type": "string", "minLength": 1, "maxLength": 1024},
            "reviewer": {"type": "string", "pattern": "^[A-Za-z0-9_.:/@+-]{1,256}$"},
            "run": opt({"type": "string", "pattern": "^run:sha256:[0-9a-f]{64}$"}),
            "created_at": _WHEN, "signature": SIG})),
    "tine-graph-1": doc("tine-graph-1", "tine code-graph --json",
        "The code map (`tine-graph/1`): every source file's symbols and imports, the import "
        "edges between files of the repository, and which parser produced each file "
        "(`tree-sitter` with the `graph` extra, else `regex`). The MCP `code_graph` tool "
        "returns the same document.",
        closed(["command", "schema", "backend", "tree_sitter", "files", "edges", "counts"], {
            "command": {"const": "code-graph"}, "schema": {"const": "tine-graph/1"},
            "backend": {"enum": ["tree-sitter", "regex", "mixed"]}, "tree_sitter": BOOL,
            "files": {"type": "array", "items": _FILE},
            "edges": {"type": "array", "items": closed(["from", "to"], {
                "from": _PATH, "to": _PATH})},
            "counts": open_(["files", "symbols", "edges"], {
                "files": INT, "symbols": INT, "edges": INT})})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {"code-graph": "tine-graph-1"}
KIND_SCHEMAS: dict[str, str] = {"opentine.review-finding": "opentine-review-finding-1"}

__all__ = ["COMMAND_SCHEMAS", "KIND_SCHEMAS", "SCHEMAS"]
