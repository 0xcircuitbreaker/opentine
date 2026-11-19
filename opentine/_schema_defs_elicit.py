"""JSON Schemas for elicitation links and the elicit report (0.68).

``tine-cli-elicit-1`` is the ``--json`` output of ``tine elicit link|report``.
``opentine-elicit-link-1`` is a signed file convention (docs/ELICITATION.md),
not an object kind.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, NUM, SIG, STR, closed, doc, opt

_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_SCORE = {"type": "string", "pattern": "^(0|1|0\\.[0-9]{0,5}[1-9])$"}
_DEC = {"type": "string", "pattern": "^-?[0-9]+\\.[0-9]{6}$"}
_KINDS = ["prompt", "scaffold", "fine-tune", "best-of-n", "eval-cue", "deployment-cue"]
_CUE = {"enum": ["eval", "deployment", "none"]}
_EFFORT = closed(["attempts", "best_of_n", "tokens", "usd", "gpu_hours"], {
    "attempts": INT, "best_of_n": opt(INT), "tokens": opt(INT), "usd": opt(NUM),
    "gpu_hours": opt(NUM)})  # fmt: skip
LINK = closed([
    "convention", "task", "safety_relevant", "condition", "model", "effort", "items",
    "created_at"], {
    "convention": {"const": "opentine.elicit-link/1"}, "task": STR, "safety_relevant": BOOL,
    "condition": closed(["name", "kind", "ref", "cue", "monitored"], {
        "name": STR, "kind": {"enum": _KINDS}, "ref": opt(STR), "cue": _CUE,
        "monitored": BOOL}),
    "model": closed(["id", "version"], {"id": STR, "version": STR}), "effort": _EFFORT,
    "items": {"type": "array", "items": closed(["id", "score"], {"id": STR, "score": _SCORE})},
    "created_at": STR, "signer": _DIGEST, "signature": SIG})  # fmt: skip
_FINDING = closed(["level", "code", "subject", "message"], {
    "level": {"enum": ["fail", "advisory"]},
    "code": {"type": "string", "pattern": "^(fail|advisory):elicit\\.[a-z-]+$"},
    "subject": opt(STR), "message": STR})  # fmt: skip
_CONDITION = closed([
    "name", "kind", "ref", "cue", "monitored", "tasks", "safety_tasks", "n", "mean", "effort",
    "gap"], {
    "name": STR, "kind": {"enum": _KINDS}, "ref": opt(STR), "cue": _CUE, "monitored": BOOL,
    "tasks": {"type": "array", "items": STR}, "safety_tasks": {"type": "array", "items": STR},
    "n": INT, "mean": _DEC, "effort": _EFFORT,
    "gap": opt(closed(["n", "delta", "ci"], {
        "n": INT, "delta": _DEC, "ci": {"type": "array", "items": _DEC}}))})  # fmt: skip
_TEST = closed(["test", "suspect", "control", "n", "delta", "p_value", "threshold", "flagged"], {
    "test": {"enum": ["underperformance", "distribution"]}, "suspect": STR, "control": STR,
    "n": INT, "delta": _DEC, "p_value": _DEC, "threshold": _DEC, "flagged": BOOL})  # fmt: skip
_HEAD = {"schema": {"const": "tine-cli-elicit/1"}}
_SHAPES = [
    closed(["command", "schema", "task", "condition", "record", "signer", "items", "path"], {
        **_HEAD, "command": {"const": "elicit link"}, "task": STR, "condition": STR,
        "record": _DIGEST, "signer": _DIGEST, "items": INT, "path": STR}),
    closed(["command", "schema", "ok", "signers", "convention", "records", "alpha", "seed",
            "resamples", "reference", "conditions", "tests", "correction", "methods",
            "findings", "note"], {
        **_HEAD, "command": {"const": "elicit report"}, "ok": BOOL,
        "signers": {"enum": ["pinned", "unpinned"]},
        "convention": {"const": "opentine.elicit-report/1"}, "records": INT, "alpha": STR,
        "seed": INT, "resamples": INT, "reference": opt(STR),
        "conditions": {"type": "array", "items": _CONDITION},
        "tests": {"type": "array", "items": _TEST},
        "correction": closed(["method", "tests", "per_test_alpha"], {
            "method": {"const": "bonferroni"}, "tests": INT, "per_test_alpha": _DEC}),
        "methods": closed(["gap", "underperformance", "distribution"], {
            "gap": {"const": "paired-bootstrap"}, "underperformance": {"const": "permutation"},
            "distribution": {"const": "paired-swap-variance"}}),
        "findings": {"type": "array", "items": _FINDING}, "note": STR}),
]  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-elicit-1": doc("tine-cli-elicit-1", "tine elicit ... --json",
        "`link` signs and files an opentine.elicit-link/1 record; `report` gives the "
        "capability gap across elicitation conditions with paired-bootstrap intervals and "
        "advisory, Bonferroni-corrected under-performance and score-distribution tests "
        "between eval-cued/monitored and deployment-cued conditions.",
        {"anyOf": _SHAPES}),
    "opentine-elicit-link-1": doc("opentine-elicit-link-1", "opentine.elicit-link/1",
        "One task attempted under one elicitation condition: the condition (kind, ref, cue, "
        "monitored), the effort record and per-item scores, signed. A file convention, not "
        "an object kind.", LINK),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    "elicit link": "tine-cli-elicit-1",
    "elicit report": "tine-cli-elicit-1",
}

__all__ = ["COMMAND_SCHEMAS", "LINK", "SCHEMAS"]
