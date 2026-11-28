"""JSON Schema for ``tine lineage diff --json`` (0.88).

A CLI output, not an object kind: a signed diff is an existing attestation
payload whose claim follows the ``opentine.lineage.diff`` convention
(docs/LINEAGE.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt

_SHA = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_HEAD = {"command": {"const": "lineage diff"}, "schema": {"const": "tine-cli-lineage-diff/1"}}
_CHANGE = {"type": "object", "required": ["op"], "properties": {
    "op": {"enum": ["added", "removed", "changed", "reordered", "insert", "delete",
                    "replace"]},
    "item": STR, "at": INT, "before": opt(STR), "after": opt(STR),
    "flags": {"type": "array", "items": STR}}}  # fmt: skip
_FLAGS = {"type": "array", "items": {"enum": ["invisible", "bidi", "non-ascii", "nfkc",
                                              "line-endings", "whitespace"]}}  # fmt: skip
_FILE = {"type": "object",
         "required": ["path", "before", "after", "status", "kind", "structural", "changes",
                      "flags"],
         "properties": {
             "path": STR, "before": opt(_SHA), "after": opt(_SHA),
             "status": {"enum": ["added", "removed", "changed"]},
             "kind": {"enum": ["python", "prompt", "tools", "config", "text", "binary"]},
             "structural": BOOL, "changes": {"type": "array", "items": _CHANGE},
             "flags": _FLAGS, "inserted": INT, "deleted": INT, "truncated": BOOL,
             "note": STR}}  # fmt: skip
_SIDE = closed(["tree", "variant", "bound"], {"tree": _SHA, "variant": opt(_SHA),
                                              "bound": opt(BOOL)})  # fmt: skip
_TOTALS = closed(
    ["files", "changed", "structural", "flagged"],
    {"files": INT, "changed": INT, "structural": INT, "flagged": INT},
)
CLAIM = closed(["convention", "from", "to", "totals", "files"], {
    "convention": {"const": "opentine.lineage.diff"}, "from": _SIDE, "to": _SIDE,
    "totals": _TOTALS, "files": {"type": "array", "items": _FILE}})  # fmt: skip
_FINDING = closed(["code", "detail"], {
    "code": {"enum": ["lineage-diff.bad-signature", "lineage-diff.mismatch"]},
    "detail": STR})  # fmt: skip
_DIFF = closed(["command", "schema", "mode", "ok", "signed", "claim"], {
    **_HEAD, "mode": {"const": "diff"}, "ok": {"const": True}, "signed": opt(STR),
    "claim": CLAIM})  # fmt: skip
_CHECK = closed(["command", "schema", "mode", "ok", "signer", "target", "bound", "findings",
                 "totals"], {
    **_HEAD, "mode": {"const": "check"}, "ok": BOOL, "signer": opt(STR), "target": opt(STR),
    "bound": {"enum": ["recomputed", "unverified"]},
    "findings": {"type": "array", "items": _FINDING}, "totals": opt(_TOTALS)})  # fmt: skip
_TREE = closed(["command", "schema", "mode", "ok", "trees"], {
    **_HEAD, "mode": {"const": "tree"}, "ok": {"const": True},
    "trees": {"type": "array", "items": closed(["path", "tree"], {"path": STR,
                                                                   "tree": _SHA})}})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-lineage-diff-1": doc("tine-cli-lineage-diff-1", "tine lineage diff --json",
        "The structural diff between two variant trees. `diff` carries the "
        "`opentine.lineage.diff` claim (files whose bytes differ, each with both digests, "
        "a kind, whether the structure changed, the changes and hidden-edit flags) and "
        "`signed`, the signed diff file when `--key` was given; `check` re-verifies one "
        "(exit 1 when `ok` is false); `tree` prints each path's tree digest.",
        {"oneOf": [_DIFF, _CHECK, _TREE]}),
}  # fmt: skip

__all__ = ["CLAIM", "SCHEMAS"]
