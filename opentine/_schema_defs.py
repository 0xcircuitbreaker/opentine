"""JSON Schemas (2020-12) for the object kinds OpenTine writes (0.45).

Each entry is keyed by its file stem: the schema tag with ``/`` spelled ``-``
(``tine-verify-report/2`` is ``tine-verify-report-2.schema.json``). These
describe documents as the reference implementation writes them today; within a
major version fields are added, never renamed or removed, so object schemas set
``additionalProperties`` only where the format itself is closed. The
``--json`` output schemas are in :mod:`opentine._schema_defs_cli`.
"""

from __future__ import annotations

from typing import Any

from opentine._verify_report import JSON_SCHEMA as VERIFY_REPORT

BASE = "https://opentine.com/schemas/"
STR: dict[str, Any] = {"type": "string"}
INT: dict[str, Any] = {"type": "integer", "minimum": 0}
NUM: dict[str, Any] = {"type": "number"}
BOOL: dict[str, Any] = {"type": "boolean"}
OBJ: dict[str, Any] = {"type": "object"}
FPR: dict[str, Any] = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
SIG = {"$ref": "tine-sig-3.schema.json"}
TIME = {"type": "string", "description": "RFC 3339 UTC timestamp"}


def strs() -> dict[str, Any]:
    return {"type": "array", "items": STR}


def opt(schema: dict[str, Any]) -> dict[str, Any]:
    """*schema* or null."""
    return {"anyOf": [schema, {"type": "null"}]}


def doc(name: str, title: str, description: str, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{BASE}{name}.schema.json",
        "title": title,
        "description": description,
        **body,
    }


def closed(required: list[str], props: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"type": "object", "additionalProperties": False, "required": required,
            "properties": props, **extra}  # fmt: skip


def open_(required: list[str], props: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"type": "object", "required": required, "properties": props, **extra}


BLAME_LINES = open_(["command", "schema", "path", "revision", "lines", "total_lines", "ai_lines"], {
    "command": {"const": "blame"}, "schema": {"const": "tine-blame/1"}, "path": STR,
    "revision": STR, "total_lines": INT,
    "ai_lines": INT, "lines": {"type": "array", "items": open_(
        ["line", "commit", "orig_path", "orig_line", "author", "author_mail", "author_time",
         "summary", "text", "ai"], {
            "line": INT, "commit": STR, "orig_path": STR, "orig_line": INT, "author": STR,
            "author_mail": STR, "author_time": INT, "summary": STR, "text": STR,
            "ai": opt(open_(["run", "seq", "model"], {"run": STR, "seq": opt(INT),
                                                     "model": STR}))})},
})  # fmt: skip

STEP_KEYS = ["id", "kind", "parent_ids", "provider", "model", "cost", "duration", "timestamp",
             "inputs", "outputs", "usage", "billing", "error", "tool"]  # fmt: skip
STEP = open_(STEP_KEYS, {
    "id": STR, "short_id": STR, "kind": STR, "parent_ids": strs(), "provider": STR,
    "model": {"type": ["object", "string", "null"]}, "cost": opt(NUM), "duration": opt(NUM),
    "timestamp": opt(NUM), "inputs": True, "outputs": True, "usage": opt(OBJ),
    "billing": opt(OBJ), "error": True, "tool": {"type": ["object", "string", "null"]},
})  # fmt: skip
RUN_KEYS = ["id", "status", "model", "created_at", "total_cost", "step_count", "tags",
            "user_prompt", "system_prompt"]  # fmt: skip
RUN = open_(RUN_KEYS, {
    "id": STR, "short_id": STR, "status": STR, "model": {"type": ["object", "string", "null"]},
    "created_at": opt(NUM), "total_cost": NUM, "step_count": INT, "tags": strs(),
    "user_prompt": True, "system_prompt": True,
})  # fmt: skip
TIERS = {"enum": ["T0", "T1", "T2", "T3"]}
ASSURANCE = open_(["claimed", "verified"], {
    "claimed": TIERS, "verified": TIERS, "witness": opt(STR), "reasons": strs(),
})  # fmt: skip
RANGE = closed(["start_line", "end_line"], {"start_line": INT, "end_line": INT})
_EVAL_SCORE = {"type": ["number", "boolean", "null"]}

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-sig-3": doc("tine-sig-3", "tine-sig/3 signed-document block",
        "The Ed25519 block _signed_doc writes into signed JSON documents (SPEC Part 4).",
        open_(["scheme", "alg", "value"], {
            "scheme": {"const": "tine-sig/3"}, "alg": STR, "signer": STR,
            "value": {"type": "string", "pattern": "^[0-9a-f]+$"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]+$"}, "key_id": STR,
            "signed_at": STR, "subject": STR,
        })),
    "tine-step-1": doc("tine-step-1", "Step", "One recorded step as `tine show --json` "
        "renders it; `repo-show` omits short_id.", STEP),
    "tine-run-1": doc("tine-run-1", "Run", "The run summary object of `tine show --json` "
        "(`run`); `repo-show` omits short_id.", RUN),
    "tine-verify-report-2": {**VERIFY_REPORT, "description": "What `tine verify RUN "
        "--offline --json` writes (SPEC, offline verification). /1 is /2 without "
        "signing_time, signature and signature_timestamps."},
    "tine-assurance-1": doc("tine-assurance-1", "Assurance", "Claimed and verified "
        "assurance tier of a run (_assurance.assess): T0 self-reported .. T3 witnessed "
        "and timestamped. `verified` never exceeds what was checked.", ASSURANCE),
    "opentine-line-attribution-1": doc("opentine-line-attribution-1",
        "opentine-line-attribution/1", "The record `tine git attribute` stores in a "
        "commit's refs/notes/tine note after `Tine-Attribution: `.",
        open_(["schema", "files", "lines_added", "lines_attributed"], {
            "schema": {"const": "opentine-line-attribution/1"}, "lines_added": INT,
            "lines_attributed": INT, "signature": SIG,
            "files": {"type": "array", "items": open_(["path", "ranges"], {
                "path": STR, "ranges": {"type": "array", "items": open_(
                    ["start_line", "end_line", "content_hash", "run", "step"], {
                        "start_line": INT, "end_line": INT, "content_hash": STR,
                        "run": STR, "step": STR, "seq": INT, "tool": STR, "model": STR})}})},
        })),
    "tine-blame-1": doc("tine-blame-1", "tine-blame/1", "One of two shapes: "
        "`tine blame PATH[:LINE] --json`, the recorded writes that inserted a line or wrote "
        "a file, or `tine blame FILE --lines --json`, one row per line with `ai` set "
        "from the attribution notes.",
        {"type": "object", "anyOf": [BLAME_LINES, open_(
            ["command", "path", "line", "commit", "linked_runs", "hits"], {
            "command": {"const": "blame"}, "schema": {"const": "tine-blame/1"},
            "path": STR, "line": opt(INT), "commit": STR, "linked_runs": {"type": "array"},
            "hits": {"type": "array", "items": open_(
                ["run_id", "step_id", "seq", "tool", "model", "agent", "ts", "path", "match"],
                {"run_id": STR, "step_id": STR, "seq": INT, "tool": STR, "model": STR,
                 "agent": STR, "ts": NUM, "path": STR, "match": {"enum": ["line", "file"]},
                 "commit": STR})},
        })]}),
    "agent-trace-0.1": doc("agent-trace-0.1", "Agent Trace record (OpenTine export)",
        "`tine export --format agent-trace`: the subset of agent-trace.dev trace-record "
        "v0.1 OpenTine writes. The upstream schema is authoritative.",
        open_(["version", "id", "timestamp", "files"], {
            "version": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+$"}, "id": STR,
            "timestamp": TIME, "tool": open_(["name"], {"name": STR, "version": STR}),
            "metadata": OBJ, "files": {"type": "array", "items": open_(
                ["path", "conversations"], {"path": STR, "conversations": {
                    "type": "array", "items": open_(["contributor", "ranges"], {
                        "contributor": open_(["type"], {"type": {"enum": ["ai", "human",
                            "mixed", "unknown"]}, "model_id": STR}),
                        "ranges": {"type": "array", "items": RANGE}})}})},
        })),
    "tine-eval-verdict-1": doc("tine-eval-verdict-1", "tine-eval-verdict/1 (draft)",
        "DRAFT for 0.45 `tine eval run`: one scorer's verdict on one dataset item for one "
        "run, signed with tine-sig/3. Field names are coordinated with the eval work and "
        "may gain fields before 0.45.0.",
        open_(["schema", "run", "item", "scorer", "score", "pass"], {
            "schema": {"const": "tine-eval-verdict/1"},
            "run": {"type": "string", "description": "the run's oid"}, "item": STR,
            "dataset": STR, "scorer": open_(["name"], {"name": STR, "kind": {"enum": [
                "deterministic", "regex", "llm-judge", "python"]}, "version": STR}),
            "score": _EVAL_SCORE, "pass": BOOL, "detail": STR, "judge_run": STR,
            "created_at": TIME, "signature": SIG,
        })),
    "opentine-delegation-1": doc("opentine-delegation-1", "opentine-delegation/1",
        "A principal key delegating scoped authority to an agent key (_delegation).",
        closed(["scheme", "issuer", "subject", "scope", "not_before", "not_after", "parent",
                "signature"], {
            "scheme": {"const": "opentine-delegation/1"}, "issuer": FPR, "subject": FPR,
            "scope": closed(["agents", "actions", "max_depth"], {
                "agents": {"type": "array", "items": STR, "minItems": 1},
                "actions": {"type": "array", "items": STR, "minItems": 1},
                "max_depth": INT}),
            "not_before": TIME, "not_after": TIME,
            "parent": {"anyOf": [{"const": ""}, FPR]}, "signature": SIG,
        })),
    "opentine-fleet-1": doc("opentine-fleet-1", "opentine-fleet/1", "metadata.fleet: "
        "which fleet member produced a run (a claim until signed).",
        closed(["scheme", "fleet_id", "member", "role", "parent"], {
            "scheme": {"const": "opentine-fleet/1"}, "fleet_id": STR, "member": STR,
            "role": STR, "parent": STR})),
    "opentine-tlog-receipt-1": doc("opentine-tlog-receipt-1", "opentine-tlog-receipt/1",
        "One transparency-log entry with its signed checkpoint and RFC 9162 inclusion "
        "proof; verifiable offline.",
        open_(["format", "checkpoint", "entry", "index", "inclusion", "vkey"], {
            "format": {"const": "opentine-tlog-receipt/1"},
            "checkpoint": {"$ref": "opentine-tlog-checkpoint-1.schema.json"},
            "entry": {"type": "string", "description": "base64 entry bytes"},
            "index": INT, "inclusion": True, "vkey": STR,
        })),
    "opentine-tlog-checkpoint-1": doc("opentine-tlog-checkpoint-1",
        "opentine-log/1 checkpoint", "A C2SP signed-note checkpoint: origin, size and "
        "base64 root lines, a blank line, then one or more signature lines.",
        {"type": "string", "pattern": "^[^\\n]+\\n[0-9]+\\n[A-Za-z0-9+/=]+\\n\\n(— [^\\n]+\\n)+$"}),
    "tine-cost-statement-1": doc("tine-cost-statement-1", "tine-cost-statement/1",
        "`tine cost RUN --statement`: the recorded cost aggregate, optionally signed.",
        closed(["schema", "aggregate"], {
            "schema": {"const": "tine-cost-statement/1"}, "signature": SIG,
            "aggregate": closed(["run_id", "total_cost", "total_tokens", "input_tokens",
                                 "output_tokens", "by_model", "by_kind", "currency"], {
                "run_id": STR, "total_cost": NUM, "total_tokens": INT, "input_tokens": INT,
                "output_tokens": INT, "by_model": {"type": "object",
                "additionalProperties": NUM}, "by_kind": {"type": "object",
                "additionalProperties": NUM}, "currency": {"const": "USD"}}),
        })),
}  # fmt: skip

__all__ = ["ASSURANCE", "RUN", "SCHEMAS", "STEP", "doc", "open_", "opt", "strs"]
