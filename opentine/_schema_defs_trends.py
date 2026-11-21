"""JSON Schemas for capability trends (0.72).

``tine-cli-trends-1`` is the ``tine trends --json`` output. ``opentine-trends-1``
is the ``--export`` file (inputs plus the reported numbers) that
``opentine/data/trends/recompute.mjs`` recomputes, and
``opentine-trends-task-lengths-1`` the signed task-lengths file: file
conventions, not object kinds (docs/TRENDS.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, SIG, STR, TIME, closed, doc, opt, strs

_SHA = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_DEC = {"type": "string", "pattern": "^-?[0-9]+\\.[0-9]{6}$"}
_CI = opt({"type": "array", "items": _DEC, "minItems": 2, "maxItems": 2})
_CI_OPEN = opt({"type": "array", "items": opt(_DEC), "minItems": 2, "maxItems": 2})
_MINUTES = {"type": "string", "pattern": "^(0|[1-9][0-9]{0,8})(\\.[0-9]{0,5}[1-9])?$"}
_LEVEL = closed(["mean", "ci"], {"mean": opt(_DEC), "ci": _CI})
_TEST = closed(["delta", "ci", "significant"], {"delta": opt(_DEC), "ci": _CI,
                                                "significant": BOOL})  # fmt: skip
_METRICS = {"type": "array", "items": {"enum": ["score", "pass_rate"]}}
_HORIZON = closed(["n", "lengths", "minutes", "ci", "reason", "failed_resamples"], {
    "n": INT, "lengths": INT, "minutes": opt(_DEC), "ci": _CI_OPEN,
    "reason": {"enum": [None, "fewer-than-two-lengths", "no-fit"]},
    "failed_resamples": INT})  # fmt: skip
_VERSUS = closed(["parent", "n", "regressions", "score", "pass_rate"], {
    "parent": _SHA, "n": INT, "regressions": _METRICS, "score": _TEST,
    "pass_rate": _TEST})  # fmt: skip
_VARIANT = closed(["variant", "generation", "parents", "flags", "n", "score", "pass_rate",
                   "cost_per_success", "horizon", "vs_parents"], {
    "variant": _SHA, "generation": INT, "parents": {"type": "array", "items": _SHA},
    "flags": strs(), "n": INT, "score": _LEVEL, "pass_rate": _LEVEL,
    "cost_per_success": opt(_DEC), "horizon": _HORIZON,
    "vs_parents": {"type": "array", "items": _VERSUS}})  # fmt: skip
_GENERATION = closed(["generation", "variants", "flagged", "regressions", "best"], {
    "generation": INT, "variants": INT, "flagged": INT, "regressions": INT,
    "best": opt(closed(["variant", "score", "horizon_minutes"], {
        "variant": _SHA, "score": _DEC, "horizon_minutes": opt(_DEC)}))})  # fmt: skip
_REGRESSION = closed(["variant", "parent", "metrics"], {"variant": _SHA, "parent": _SHA,
                                                        "metrics": _METRICS})  # fmt: skip
_RESULT = {
    "convention": {"const": "opentine.trends/1"},
    "alpha": STR,
    "seed": INT,
    "resamples": INT,
    "variants": {"type": "array", "items": _VARIANT},
    "generations": {"type": "array", "items": _GENERATION},
    "regressions": {"type": "array", "items": _REGRESSION},
    "flags": strs(),
}
RESULT = closed(list(_RESULT), _RESULT)
_ITEM = closed(["item", "score", "passed", "minutes"], {
    "item": STR, "score": STR, "passed": BOOL, "minutes": opt(_MINUTES)})  # fmt: skip
_INPUT = closed(["variant", "generation", "parents", "loop", "flags", "items",
                 "cost_micro_usd"], {
    "variant": _SHA, "generation": INT, "parents": {"type": "array", "items": _SHA},
    "loop": opt(STR), "flags": strs(), "items": {"type": "array", "items": _ITEM},
    "cost_micro_usd": opt(INT)})  # fmt: skip
EXPORT = closed(["convention", "alpha", "seed", "resamples", "variants", "reported"], {
    "convention": {"const": "opentine.trends/1"}, "alpha": STR, "seed": INT, "resamples": INT,
    "variants": {"type": "array", "items": _INPUT}, "reported": RESULT})  # fmt: skip
LENGTHS = closed(["kind", "suite", "dataset", "lengths", "signer", "signed_at", "signature"], {
    "kind": {"const": "opentine.trends.task-lengths/1"}, "suite": STR, "dataset": _SHA,
    "lengths": {"type": "object", "additionalProperties": _MINUTES}, "signer": FPR,
    "signed_at": TIME, "signature": SIG})  # fmt: skip
_CLI = closed(["command", "schema", "signers", "lengths", "excluded", "unchecked", "export_sha256",
               *_RESULT], {
    "command": {"const": "trends"}, "schema": {"const": "tine-cli-trends/1"},
    "signers": {"enum": ["pinned", "unpinned"]},
    "lengths": closed(["status", "suite", "signer", "dataset"], {
        "status": {"enum": ["trusted", "missing", "invalid", "roles-unpinned",
                            "signer-untrusted"]},
        "suite": opt(STR), "signer": opt(STR), "dataset": opt(_SHA)}),
    "excluded": {"type": "array", "items": closed(["variant", "code"], {
        "variant": _SHA, "code": {"enum": ["lineage.record-invalid", "lineage.cycle"]}})},
    "unchecked": {"type": "array", "items": closed(["variant", "code"], {
        "variant": _SHA, "code": {"enum": ["lineage.record-invalid", "lineage.cycle",
                                           "lineage.evidence-missing", "lineage.signer-untrusted",
                                           "trends.run-relabelled"]}})},
    "export_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, **_RESULT})  # fmt: skip
_SIGNED = closed(["command", "schema", "signed", "suite", "signer", "items"], {
    "command": {"const": "trends"}, "schema": {"const": "tine-cli-trends/1"}, "signed": STR,
    "suite": STR, "signer": FPR, "items": INT})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-trends-1": doc("tine-cli-trends-1", "tine trends --json",
        "Capability trends over lineage generations, from signed records only: per variant "
        "the mean score and pass rate with 0.57 bootstrap intervals, cost per success, the "
        "50%-success time horizon with a studentized bootstrap interval, and paired "
        "comparisons with each parent; per generation a summary. Or, with --sign-lengths, "
        "the signed task-lengths file written.", {"anyOf": [_CLI, _SIGNED]}),
    "opentine-trends-1": doc("opentine-trends-1", "opentine.trends/1 export",
        "The tine trends --export file: the inputs every number is computed from and the "
        "reported numbers, which opentine/data/trends/recompute.mjs reproduces byte for "
        "byte. A file convention, not an object kind.", EXPORT),
    "opentine-trends-task-lengths-1": doc("opentine-trends-task-lengths-1",
        "opentine.trends.task-lengths/1",
        "Signed human task lengths (minutes) per eval item, for the time horizon. Used only "
        "when signed by a pinned dataset-role key that is not an optimizer key. A file "
        "convention, not an object kind.", LENGTHS),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {"trends": "tine-cli-trends-1"}

__all__ = ["COMMAND_SCHEMAS", "EXPORT", "LENGTHS", "RESULT", "SCHEMAS"]
