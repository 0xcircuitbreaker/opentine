"""JSON Schemas for forge integration (0.48, SPEC 4.24).

``opentine-forge-check-1`` is the record ``tine forge publish`` posts (a check
run, a commit status, an MR note, a PR comment, or a git note for Entire);
``tine-cli-forge-1`` is the ``--json`` output of ``tine forge publish``. The
schemas check shape; the share, conclusion and bundle rules are the
verifier's (``opentine._forge_check``).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc, open_, opt

_ID: dict[str, Any] = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"}
_REPO_ID: dict[str, Any] = {"type": "string", "pattern": "^[A-Za-z0-9_.:/-]{1,128}$"}
_FORGE = {"enum": ["github", "gitlab", "forgejo", "entire"]}
_TARGET = {"enum": ["check-run", "status", "comment", "checkpoint", "note"]}
_CHECK = {"$ref": "opentine-forge-check-1.schema.json"}
_ROW = closed(["target", "state", "id"], {
    "target": _TARGET, "state": {"enum": ["created", "updated", "written"]},
    "id": {"anyOf": [{"type": "null"}, INT, STR]}})  # fmt: skip
_STEP = closed(["target", "method", "path"], {"target": _TARGET, "method": STR, "path": STR})
_URL = {"type": "string", "pattern": "^https://[A-Za-z0-9._~:/?#@!$&*+,;=%-]{1,2040}$"}

SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-forge-check-1": doc("opentine-forge-check-1",
        "opentine.forge-check (check_version 1)",
        "What `tine forge publish` shows on a forge for one commit (SPEC 4.24): the verify "
        "state, the AI share in parts per million (`ai_lines * 1000000 // total_lines`), the "
        "commit's AI-attributed ranges (the blame overlay, at most 50) and the digest and URL "
        "of an offline-verifiable bundle. Unsigned: `conclusion` follows `verify.state` "
        "(verified -> success, failed -> failure, unverified -> neutral).",
        closed(["kind", "check_version", "forge", "forge_repo_id", "project_id", "commit",
                "verify", "ai", "bundle", "overlay", "conclusion"], {
            "kind": {"const": "opentine.forge-check"}, "check_version": {"const": 1},
            "forge": _FORGE, "forge_repo_id": _REPO_ID, "project_id": opt(_ID),
            "commit": {"type": "string", "pattern": "^([0-9a-f]{40}|[0-9a-f]{64})$"},
            "verify": closed(["state", "runs"], {
                "state": {"enum": ["verified", "failed", "unverified"]}, "runs": INT}),
            "ai": closed(["ai_lines", "total_lines", "share_ppm"], {
                "ai_lines": INT, "total_lines": INT,
                "share_ppm": {"type": "integer", "minimum": 0, "maximum": 1000000}}),
            "bundle": closed(["url", "digest"], {
                "url": opt(_URL),
                "digest": opt({"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"})}),
            "overlay": {"type": "array", "maxItems": 50, "items": closed(
                ["path", "start_line", "end_line", "run"], {
                    "path": {"type": "string", "minLength": 1, "maxLength": 1024},
                    "start_line": {"type": "integer", "minimum": 1},
                    "end_line": {"type": "integer", "minimum": 1},
                    "run": opt({"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,128}$"})})},
            "conclusion": {"enum": ["success", "failure", "neutral"]}})),
    "tine-cli-forge-1": doc("tine-cli-forge-1", "tine forge publish --json",
        "`check` is the record posted; `posted` what was written (a check run, a status, a "
        "comment, Entire checkpoint refs or the git note); with `--dry-run`, `plan` lists the "
        "requests instead and nothing is sent. `push` (Entire) is the command that publishes "
        "the refs written. Tokens never appear.",
        open_(["command", "action", "ok", "forge", "dry_run", "check", "posted"], {
            "command": {"const": "forge"}, "action": {"const": "publish"}, "ok": BOOL,
            "forge": _FORGE, "dry_run": BOOL, "check": _CHECK,
            "posted": {"type": "array", "items": _ROW},
            "plan": {"type": "array", "items": _STEP}, "push": STR})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {"forge": "tine-cli-forge-1"}

#: ``kind`` value -> schema stem.
KIND_SCHEMAS: dict[str, str] = {"opentine.forge-check": "opentine-forge-check-1"}

__all__ = ["COMMAND_SCHEMAS", "KIND_SCHEMAS", "SCHEMAS"]
