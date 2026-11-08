"""JSON Schemas for ``tine ... --json`` output and ``tine help --json`` (0.45).

``tine-cli-envelope-1`` is the contract every ``--json`` invocation meets: one
object on stdout that names its ``command``, is the wrapping fallback object
(``command``/``exit_code``/``output``), or is an ``{"error": ...}`` object.
:data:`COMMAND_SCHEMAS` names the more specific schema for a ``command`` value
when one is published; a command without an entry is held to the envelope only.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import ASSURANCE, RUN, STEP, doc, open_, opt, strs

STR: dict[str, Any] = {"type": "string"}
INT: dict[str, Any] = {"type": "integer", "minimum": 0}
NUM: dict[str, Any] = {"type": "number"}
BOOL: dict[str, Any] = {"type": "boolean"}

ERROR = open_(["error"], {"error": open_(["code", "exit_code", "message"], {
    "code": STR, "exit_code": {"type": "integer"}, "message": STR})})  # fmt: skip
ENTRY = open_(["run_id", "short_id", "status", "model", "steps", "cost", "created_at"], {
    "run_id": STR, "short_id": STR, "status": STR, "model": {"type": ["string", "null"]},
    "steps": INT, "cost": NUM, "created_at": True, "mtime": True, "format_version": True,
    "tags": strs(), "file": STR, "unreadable": BOOL,
})  # fmt: skip
_SIGNATURE = open_(["ok", "state"], {"ok": BOOL, "state": STR})
_BUDGET = open_([], {})
_CAPTURE = open_(["path", "assurance", "actions"], {"path": STR, "actions": INT})
_FLAG = open_(["flags", "dest"], {
    "flags": strs(), "dest": STR, "help": opt(STR), "metavar": True, "nargs": True,
    "choices": opt({"type": "array"}), "required": BOOL, "takes_value": BOOL, "default": True,
})  # fmt: skip
_HELP_NODE: dict[str, Any] = open_(["name", "summary", "flags", "subcommands"], {
    "name": STR, "summary": STR, "advanced": BOOL, "usage": STR,
    "flags": {"type": "array", "items": _FLAG},
    "subcommands": {"type": "array", "items": {"$ref": "#/$defs/command"}},
})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-envelope-1": doc("tine-cli-envelope-1", "tine --json envelope",
        "Every `tine ... --json` writes exactly one JSON object to stdout: a command's own "
        "object (it names `command`), the fallback wrapper of a command without its own "
        "JSON (`command`, `exit_code`, `output`), or an error object. The five v3 plumbing "
        "verbs (fsck, object, migrate-v3, fetch, push) print bare JSON and are exempt.",
        {"$defs": {"error": ERROR, "fallback": open_(["command", "exit_code", "output"], {
            "command": STR, "exit_code": {"type": "integer"}, "output": STR})},
         "type": "object", "anyOf": [
            open_(["command"], {"command": {"type": "string", "minLength": 1}}),
            {"$ref": "#/$defs/error"}]}),
    "tine-cli-show-1": doc("tine-cli-show-1", "tine show --json", "One run and its steps.",
        open_(["command", "path", "run", "steps"], {
            "command": {"const": "show"}, "path": STR,
            "run": {"$ref": "tine-run-1.schema.json"},
            "steps": {"type": "array", "items": {"$ref": "tine-step-1.schema.json"}},
            "assurance": {"$ref": "tine-assurance-1.schema.json"}})),
    "tine-cli-verify-1": doc("tine-cli-verify-1", "tine verify --json (online)",
        "One of three shapes, all `command: verify`: the integrity and signature verdict "
        "(the default), an in-toto attestation verdict (`--attestation`, it names "
        "`attestation`) or a capture comparison (`mode: compare-capture`). `--offline` "
        "writes tine-verify-report/2 instead.",
        {"type": "object", "properties": {"command": {"const": "verify"}},
         "required": ["command"], "anyOf": [
            open_(["path", "ok", "integrity", "signature"], {
                "path": STR, "ok": BOOL,
                "integrity": open_(["ok", "algorithm", "expected", "actual", "reason",
                                    "draft"], {"ok": BOOL, "draft": BOOL}),
                "signature": opt(_SIGNATURE), "assurance": ASSURANCE}),
            open_(["attestation", "path", "ok", "signature", "subject", "receipt"], {
                "attestation": STR, "path": opt(STR), "ok": BOOL,
                "signature": open_(["status", "reason"], {"status": STR}),
                "subject": open_(["ok", "reason"], {"ok": BOOL, "reason": opt(STR)}),
                "receipt": opt({"type": "object"}), "predicate_type": opt(STR)}),
            open_(["mode", "witness", "other", "consistent", "divergences"], {
                "mode": {"const": "compare-capture"}, "consistent": BOOL,
                "witness": _CAPTURE, "other": _CAPTURE,
                "divergences": {"type": "array", "items": open_(["kind"], {
                    "kind": {"enum": ["changed", "missing", "unwitnessed"]}})}}),
        ]}),
    "tine-verify-dataset-1": doc("tine-verify-dataset-1", "tine-verify-dataset/1",
        "What `tine verify --offline DIR|REPO --json` writes: one verdict per run and a "
        "Merkle root over (run_id, digest) (SPEC 8.3). A directory's runs embed their "
        "tine-verify-report/2.",
        open_(["schema", "command", "offline", "path", "kind", "strict", "verdict", "ok",
               "count", "merkle", "checks", "runs"], {
            "schema": {"const": "tine-verify-dataset/1"}, "command": {"const": "verify"},
            "offline": {"const": True}, "path": STR, "kind": STR, "strict": BOOL,
            "verdict": {"enum": ["pass", "fail"]}, "ok": BOOL, "count": INT,
            "merkle": open_(["algorithm", "root"], {
                "algorithm": STR, "root": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}),
            "checks": {"type": "array", "items": open_(["name", "ok", "detail"], {
                "name": STR, "ok": BOOL, "detail": STR})},
            "runs": {"type": "array", "items": open_(["run_id", "digest", "ok"], {
                "run_id": STR, "path": STR, "digest": STR, "ok": BOOL, "failed": strs(),
                "reason": opt(STR),
                "report": {"$ref": "tine-verify-report-2.schema.json"}})}})),
    "tine-cli-runs-1": doc("tine-cli-runs-1", "tine ls / search --json",
        "Legacy index rows; `query` on search only.",
        open_(["command", "count", "runs"], {
            "command": {"enum": ["ls", "search"]}, "query": STR, "count": INT,
            "runs": {"type": "array", "items": ENTRY}})),
    "tine-cli-cost-1": doc("tine-cli-cost-1", "tine cost --json",
        "The run's recorded cost breakdown and budget state.",
        open_(["command", "run_id", "total_cost", "total_tokens", "by_model", "by_kind",
               "budget", "budget_state", "over_budget"], {
            "command": {"const": "cost"}, "run_id": STR, "short_id": STR, "total_cost": NUM,
            "total_tokens": INT, "input_tokens": INT, "output_tokens": INT,
            "by_model": {"type": "object", "additionalProperties": NUM},
            "by_kind": {"type": "object", "additionalProperties": NUM},
            "budget": opt(_BUDGET), "budget_state": opt(_BUDGET), "over_budget": BOOL})),
    "tine-search-results-1": doc("tine-search-results-1", "tine repo-search --json",
        "Search results over a v3 repository with the filters that produced them.",
        open_(["command", "repo", "query", "count", "results"], {
            "command": {"const": "repo-search"}, "repo": STR, "query": STR,
            "successful_only": BOOL, "signed_only": BOOL, "limit": INT,
            "min_score": opt(NUM), "model": opt(STR), "count": INT,
            "remote": opt(STR), "truncated": BOOL,  # 0.46: repo-search --remote
            "results": {"type": "array", "items": open_(["run_id", "status"], {
                "run_id": STR, "status": STR, "score": opt(NUM), "cost": opt(NUM),
                "latency": opt(NUM), "models": strs(), "matched_text": opt(STR)})}})),
    "tine-ai-share-1": doc("tine-ai-share-1", "tine-ai-share/1", "The share of lines "
        "attribution notes credit to agents. One of two shapes: `tine stats --ai-share "
        "--json` (every line at a revision, by git blame) or `tine git share-line --json`, "
        "the post-commit AI-share line (the lines one commit added).",
        {"type": "object", "anyOf": [open_(
            ["command", "schema", "revision", "total_lines", "ai_lines", "ai_share", "files"], {
                "command": {"const": "stats"}, "schema": {"const": "tine-ai-share/1"},
                "mode": {"const": "ai-share"}, "revision": STR, "total_lines": INT,
                "ai_lines": INT, "ai_share": {"type": "number", "minimum": 0, "maximum": 1},
                "by_model": {"type": "object", "additionalProperties": INT},
                "commits_with_attribution": INT, "files_clipped": BOOL,
                "files": {"type": "array", "items": open_(["path", "lines", "ai_lines"], {
                    "path": STR, "lines": INT, "ai_lines": INT})}}),
            open_(["command", "schema", "commit", "lines_added", "lines_attributed",
                   "ai_share", "line"], {
                "command": {"const": "share-line"}, "schema": {"const": "tine-ai-share/1"},
                "commit": STR, "lines_added": INT, "lines_attributed": INT,
                "ai_share": {"type": "number", "minimum": 0, "maximum": 1},
                "line": STR})]}),
    "tine-repo-show-1": doc("tine-repo-show-1", "tine repo-show --json",
        "A v3 run by ref or oid; run and step objects without short_id.",
        open_(["command", "repo", "ref", "run_object_id", "run", "steps"], {
            "command": {"const": "repo-show"}, "repo": STR, "ref": STR,
            "run_object_id": STR, "run": RUN, "steps": {"type": "array", "items": STEP}})),
    "tine-help-1": doc("tine-help-1", "tine help --json",
        "The machine-readable command and flag tree the web's generated CLI docs read.",
        {"$defs": {"command": _HELP_NODE},
         **open_(["command", "schema", "version", "prog", "commands"], {
            "command": {"const": "help"}, "schema": {"const": "tine-help/1"},
            "version": STR, "prog": STR,
            "global_flags": {"type": "array", "items": _FLAG},
            "commands": {"type": "array", "items": {"$ref": "#/$defs/command"}}})}),
}  # fmt: skip

#: ``command`` value -> schema stem for the outputs with a published schema.
COMMAND_SCHEMAS: dict[str, str] = {
    "show": "tine-cli-show-1",
    "verify": "tine-cli-verify-1",
    "ls": "tine-cli-runs-1",
    "search": "tine-cli-runs-1",
    "cost": "tine-cli-cost-1",
    "repo-search": "tine-search-results-1",
    "repo-show": "tine-repo-show-1",
    "blame": "tine-blame-1",
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
