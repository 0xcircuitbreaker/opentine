"""JSON Schema for ``tine agent scaffold | scaffold-diff | scaffold-pin --json`` (0.88).

A CLI output, not an object kind: a recorded manifest is an existing
attestation under the ``opentine.scaffold-manifest/1`` claim convention, and the
signed glob list one under ``opentine.scaffold-files/1`` (docs/SCAFFOLD.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt, strs

_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_HEAD = {"schema": {"const": "tine-cli-scaffold/1"}}
_ROW = closed(["path", "kind", "sha256", "bytes", "target", "resolved", "via"], {
    "path": STR, "kind": {"enum": ["file", "link", "special", "external", "missing"]},
    "sha256": opt(_HEX), "bytes": opt(INT), "target": opt(STR), "resolved": opt(STR),
    "via": opt(STR)})  # fmt: skip
MANIFEST = closed(["schema", "harness", "source", "globs", "files", "tree_sha256"], {
    "schema": {"const": "opentine.scaffold-manifest/1"}, "harness": STR,
    "source": {"enum": ["default", "pinned"]}, "globs": strs(),
    "files": {"type": "array", "items": _ROW}, "tree_sha256": _HEX})  # fmt: skip
_SIDE = closed(["kind", "sha256", "target", "resolved"], {
    "kind": STR, "sha256": opt(_HEX), "target": opt(STR), "resolved": opt(STR)})  # fmt: skip
_SCAFFOLD = closed(["command", "schema", "manifest", "record"], {
    **_HEAD, "command": {"const": "agent scaffold"}, "manifest": MANIFEST,
    "record": opt(STR)})  # fmt: skip
_DIFF = closed(["command", "schema", "before_tree", "after_tree", "added", "removed", "changed",
                "same"], {
    **_HEAD, "command": {"const": "agent scaffold-diff"}, "before_tree": _HEX,
    "after_tree": _HEX, "added": strs(), "removed": strs(), "same": BOOL,
    "changed": {"type": "array", "items": closed(["path", "before", "after"], {
        "path": STR, "before": _SIDE, "after": _SIDE})}})  # fmt: skip
_PIN = closed(["command", "schema", "harnesses", "signer", "pin"], {
    **_HEAD, "command": {"const": "agent scaffold-pin"},
    "harnesses": {"type": "object", "additionalProperties": strs()}, "signer": STR,
    "pin": STR})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-scaffold-1": doc("tine-cli-scaffold-1", "tine agent scaffold VERB --json",
        "Scaffold manifests (0.88). `scaffold` digests every scaffold file of a harness "
        "(instruction files and their `@path` imports, settings, hooks, skills, commands, "
        "agents, rules, MCP configuration) under `--root`; `record` is the attestation id "
        "when `--record RUN` signed it onto a stored run. `scaffold-diff` compares two "
        "manifests path by path. `scaffold-pin` signs the glob list that replaces a "
        "harness's defaults with a policy-role key.",
        {"oneOf": [_SCAFFOLD, _DIFF, _PIN]}),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"agent {name}": "tine-cli-scaffold-1" for name in ("scaffold", "scaffold-diff", "scaffold-pin")
}

__all__ = ["COMMAND_SCHEMAS", "MANIFEST", "SCHEMAS"]
