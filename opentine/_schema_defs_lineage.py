"""JSON Schema for ``tine lineage record|check|graph|why|archive|index --json`` (0.58).

A CLI output, not an object kind: lineage records are existing attestations
whose claim follows the ``opentine.lineage.variant`` convention (docs/LINEAGE.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt, strs

_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_SHA = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_SHAS = {"type": "array", "items": _SHA}
_NODE = closed(["variant", "oid", "signer", "signed", "loop", "evidence"],
               {"variant": _SHA, "oid": _SHA, "signer": STR, "signed": BOOL, "loop": STR,
                "evidence": INT})  # fmt: skip
_EDGE = closed(["child", "parent"], {"child": _SHA, "parent": _SHA})
_ANCESTOR = closed(["variant", "depth", "oid", "signer", "signed", "loop"],
                   {"variant": _SHA, "depth": INT, "oid": _SHA, "signer": STR, "signed": BOOL,
                    "loop": STR})  # fmt: skip
_EVIDENCE = closed(["variant", "kind", "ref", "detail"],
                   {"variant": _SHA, "kind": STR, "ref": STR, "detail": STR})  # fmt: skip
_MEMBER = closed(["variant", "signed", "loop", "parents", "children"],
                 {"variant": _SHA, "signed": BOOL, "loop": STR, "parents": INT,
                  "children": INT})  # fmt: skip
_TOTALS = closed(["variants", "signed", "roots", "leaves", "multi_parent", "max_parents"],
                 {"variants": INT, "signed": INT, "roots": INT, "leaves": INT,
                  "multi_parent": INT, "max_parents": INT})  # fmt: skip
_HEAD = {"schema": {"const": "tine-cli-lineage/1"}}
_CODES = ("variant-unknown", "record-invalid", "parent-missing", "cycle", "evidence-missing",
          "decision-mismatch", "signer-untrusted", "score-tainted")  # fmt: skip
_SIGNERS = {"enum": ["pinned", "unpinned"]}
_FINDING = closed(
    ["code", "variant", "detail"],
    {"code": {"enum": [f"lineage.{c}" for c in _CODES]}, "variant": _SHA, "detail": STR},
)
_FINDINGS = {"type": "array", "items": _FINDING}
_EVAL = closed(["eval", "verdicts_sha256"], {"eval": _SHA, "verdicts_sha256": _HEX})

_RECORD = closed(["command", "schema", "ok", "variant", "record", "parents", "evals",
                  "decision"], {
    **_HEAD, "command": {"const": "lineage record"}, "ok": {"const": True}, "variant": _SHA,
    "record": STR, "parents": _SHAS, "evals": {"type": "array", "items": _EVAL},
    "decision": opt(closed(["sha256"], {"sha256": _HEX}))})  # fmt: skip
_CHECK = closed(["command", "schema", "ok", "variant", "signers", "ancestors", "findings"], {
    **_HEAD, "command": {"const": "lineage check"}, "ok": BOOL, "variant": _SHA,
    "signers": _SIGNERS,
    "ancestors": _SHAS, "findings": _FINDINGS})  # fmt: skip

_GRAPH = closed(["command", "schema", "nodes", "edges", "missing_parents", "cyclic",
                 "graph_sha256"], {
    **_HEAD, "command": {"const": "lineage graph"}, "nodes": {"type": "array", "items": _NODE},
    "edges": {"type": "array", "items": _EDGE}, "missing_parents": _SHAS, "cyclic": _SHAS,
    "graph_sha256": _HEX})  # fmt: skip
_WHY = closed(["command", "schema", "variant", "depth", "ancestors", "evidence", "summary",
               "missing_parents", "truncated", "store_checked", "visited", "ok", "signers",
               "findings"], {
    **_HEAD, "command": {"const": "lineage why"}, "variant": _SHA, "depth": INT,
    "ok": BOOL, "signers": _SIGNERS, "findings": _FINDINGS,
    "ancestors": {"type": "array", "items": _ANCESTOR},
    "evidence": {"type": "array", "items": _EVIDENCE},
    "summary": {"type": "object", "additionalProperties": strs()},
    "missing_parents": _SHAS, "truncated": BOOL, "store_checked": BOOL,
    "rebuilt": {"const": True},
    "visited": closed(["queries", "rows"], {"queries": INT, "rows": INT})})  # fmt: skip
_ARCHIVE = closed(["command", "schema", "loop", "signed_only", "totals", "members"], {
    **_HEAD, "command": {"const": "lineage archive"}, "loop": opt(STR), "signed_only": BOOL,
    "totals": _TOTALS, "members": {"type": "array", "items": _MEMBER}})  # fmt: skip
_INDEX = closed(["command", "schema", "variants", "edges", "graph_sha256", "path"], {
    **_HEAD, "command": {"const": "lineage index"}, "variants": INT, "edges": INT,
    "graph_sha256": _HEX, "path": STR})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-lineage-1": doc("tine-cli-lineage-1",
        "tine lineage record|check|graph|why|archive|index --json",
        "The self-modification lineage of a self-improving agent loop. `record` names the "
        "variant id it signed (claim convention `opentine.lineage.variant`), the record file, "
        "its parents, justifying evals and cited decision. `check` walks the variant's "
        "ancestry over the lineage folder: `ancestors` in depth-first order, `findings` each "
        "a `lineage.*` code about one variant; `ok` only when there is none (exit 1 "
        "otherwise). `signers` is `pinned` when `.tine/key-roles.toml` or a promotion "
        "policy pins eval signers (an untrusted one is `lineage.signer-untrusted`) and "
        "`unpinned` otherwise: a warning that signers are proven, not trusted. `graph`, "
        "`why`, `archive` and `index` read the derived index "
        "`LINEAGE_FOLDER/index/lineage.sqlite` (rebuildable, never authoritative): `graph` "
        "lists variants and parent edges with `graph_sha256`, equal for equal graphs; `why` "
        "walks one variant to every ancestor and its evidence (evals, judges, dataset "
        "commitments, approvers, policies, decisions), reporting the index rows `visited`, "
        "and carries `check`'s `ok` and `findings` (exit 1 when not ok); `archive` "
        "summarises a population with non-linear parents; `index` builds it.",
        {"oneOf": [_RECORD, _CHECK, _GRAPH, _WHY, _ARCHIVE, _INDEX]}),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"lineage {name}": "tine-cli-lineage-1"
    for name in ("record", "check", "graph", "why", "archive", "index")
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
