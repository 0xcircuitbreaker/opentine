"""JSON Schemas for scorer isolation (0.85).

``tine-cli-eval-rescore-1`` and ``tine-cli-eval-lint-1`` are ``--json``
outputs. ``opentine-scorer-closure-1`` (the ``scorer.json`` eval-folder sidecar),
``opentine-scorer-contract-1`` (a contract file) and ``opentine-rescore-report-1``
(a signed file convention) are claim and file conventions
(docs/SCORER-ISOLATION.md), not object kinds.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, OBJ, SIG, STR, closed, doc, opt

_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_SCORE = {"type": "string", "pattern": "^(0|1|0\\.[0-9]{0,5}[1-9])$"}
_PIN = {"type": "string", "pattern": "^sc1\\+sha256:[0-9a-f]{64}$"}
_POS = {"type": "integer", "minimum": 1}
_FILES = {"type": "array", "items": closed(["file", "sha256"], {"file": STR, "sha256": _HEX})}
CLOSURE = closed([
    "convention", "target", "python", "modules", "data", "inputs", "lockfile", "contract",
    "isolation", "limits"], {
    "convention": {"const": "opentine.scorer-closure/1"},
    "target": {"type": "string", "pattern": "^python:"}, "python": STR,
    "modules": {"type": "array", "items": closed(["name", "sha256"],
                                                 {"name": STR, "sha256": _HEX})},
    "data": _FILES, "inputs": _FILES, "lockfile": opt(FPR), "contract": opt(FPR),
    "isolation": closed(["level", "network", "limits", "env"], {
        "level": {"enum": ["full", "partial"]}, "network": {"enum": ["namespace", "audit"]},
        "limits": BOOL, "env": {"const": "empty"}}),
    "limits": closed(["cpu_seconds", "memory_mb", "timeout_seconds", "output_bytes"], {
        "cpu_seconds": _POS, "memory_mb": _POS, "timeout_seconds": _POS,
        "output_bytes": _POS})})  # fmt: skip
CONTRACT = closed(["convention"], {
    "convention": {"const": "opentine.scorer-contract/1"}, "deterministic": BOOL,
    "anchors": {"type": "array", "items": closed(["item", "output", "score"], {
        "item": OBJ, "output": {}, "score": {"type": "number"}})},
    "output_schema": {}, "output_length": closed([], {"min": INT, "max": INT}),
    "length_relation": closed(["field", "relation"], {
        "field": STR, "relation": {"enum": ["eq", "le", "ge"]}})})  # fmt: skip
REPORT = closed([
    "convention", "eval", "dataset", "scorer_version", "closure", "rescored_closure",
    "closure_agree", "rows", "agreed", "disagreed", "verdict", "isolation", "created_at",
    "signer", "signature"], {
    "convention": {"const": "opentine.rescore-report/1"}, "eval": FPR, "dataset": FPR,
    "scorer_version": _PIN, "closure": FPR, "rescored_closure": FPR, "closure_agree": BOOL,
    "rows": {"type": "array", "items": closed(["item", "reported", "rescored", "agree"], {
        "item": STR, "reported": _SCORE, "rescored": _SCORE, "agree": BOOL})},
    "agreed": INT, "disagreed": INT, "verdict": {"enum": ["agree", "disagree"]},
    "isolation": {"enum": ["full", "partial"]}, "created_at": STR, "signer": FPR,
    "signature": SIG})  # fmt: skip
_FINDING = closed(["file", "line", "code", "detail"], {
    "file": STR, "line": INT,
    "code": {"type": "string", "pattern": "^advisory:introspection\\.[a-z-]+$"},
    "detail": STR})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-eval-rescore-1": doc("tine-cli-eval-rescore-1", "tine eval rescore --json",
        "An isolated eval's recorded scorer re-run under isolation on the named outputs; "
        "`report` is the signed opentine.rescore-report/1 and `ok` is its verdict == agree.",
        closed(["command", "schema", "ok", "report", "path"], {
            "command": {"const": "eval rescore"},
            "schema": {"const": "tine-cli-eval-rescore/1"}, "ok": BOOL, "report": REPORT,
            "path": opt(STR)})),
    "tine-cli-eval-lint-1": doc("tine-cli-eval-lint-1", "tine eval lint --json",
        "Introspection lint findings (`advisory:introspection.*`); advisory, so `ok` is "
        "false only under --strict with a finding.",
        closed(["command", "schema", "ok", "files", "findings"], {
            "command": {"const": "eval lint"}, "schema": {"const": "tine-cli-eval-lint/1"},
            "ok": BOOL, "files": INT, "findings": {"type": "array", "items": _FINDING}})),
    "opentine-scorer-closure-1": doc("opentine-scorer-closure-1", "opentine.scorer-closure/1",
        "An isolated scorer's closure (scorer.json beside the verdicts): every non-stdlib "
        "module and data file it loaded, hashed by the parent, plus interpreter, lockfile, "
        "contract, isolation level and limits. Its sc1+sha256 pin is the signed "
        "scorer_version. A claim convention, not an object kind.", CLOSURE),
    "opentine-scorer-contract-1": doc("opentine-scorer-contract-1", "opentine.scorer-contract/1",
        "An evaluator invariant contract: determinism, anchors with known scores, output "
        "shape, length bounds and a length relation to an item field. A file convention, "
        "not an object kind.", CONTRACT),
    "opentine-rescore-report-1": doc("opentine-rescore-report-1", "opentine.rescore-report/1",
        "A signed agree/disagree report for an isolated re-run of an eval's recorded scorer. "
        "A file convention, not an object kind.", REPORT),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    "eval rescore": "tine-cli-eval-rescore-1",
    "eval lint": "tine-cli-eval-lint-1",
}

__all__ = ["CLOSURE", "COMMAND_SCHEMAS", "CONTRACT", "REPORT", "SCHEMAS"]
