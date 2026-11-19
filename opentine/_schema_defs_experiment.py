"""JSON Schemas for experiment manifests and reproduce reports (0.67).

``tine-cli-experiment-1`` and ``tine-cli-reproduce-1`` are the ``--json``
outputs. ``opentine-experiment-manifest-1`` and ``opentine-reproduce-report-1``
are signed file conventions (docs/EXPERIMENTS.md), not object kinds.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, NUM, SIG, STR, closed, doc, opt

_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_SCORE = {"type": "string", "pattern": "^(0|1|0\\.[0-9]{0,5}[1-9])$"}
_DEC = {"type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$"}
_SCALAR = {"type": ["string", "number", "boolean", "null"]}
_ROW = closed(["id", "verdict", "path", "score", "passed"], {
    "id": STR, "verdict": _DIGEST, "path": STR, "score": _SCORE, "passed": BOOL,
    "input": {}})  # fmt: skip
MANIFEST = closed([
    "convention", "experiment", "hypothesis", "code_digest", "container_digest", "model",
    "sampling", "seeds", "data", "compute", "results", "conclusion", "created_at"], {
    "convention": {"const": "opentine.experiment-manifest/1"}, "experiment": STR,
    "hypothesis": STR, "code_digest": _DIGEST, "container_digest": opt(_DIGEST),
    "model": closed(["id", "version"], {"id": STR, "version": STR}),
    "sampling": {"type": "object", "additionalProperties": _SCALAR},
    "seeds": {"type": "array", "items": {"type": "integer"}},
    "data": {"type": "array", "items": closed(["name", "commitment"],
                                              {"name": STR, "commitment": _DIGEST})},
    "compute": closed(["usd", "gpu_hours", "tokens"],
                      {"usd": opt(NUM), "gpu_hours": opt(NUM), "tokens": opt(INT)}),
    "results": {"type": "array", "items": _ROW}, "conclusion": STR, "created_at": STR,
    "signer": _DIGEST, "signature": SIG})  # fmt: skip
_SELECTION = closed(
    ["seed", "k", "population", "ids"],
    {
        "seed": {"type": "integer"},
        "k": INT,
        "population": INT,
        "ids": {"type": "array", "items": STR},
    },
)
_REROW = closed(["id", "expected", "observed", "delta", "agree"], {
    "id": STR, "expected": _SCORE, "observed": {"type": "array", "items": _DEC},
    "delta": _DEC, "agree": BOOL})  # fmt: skip
REPORT = closed([
    "convention", "experiment", "manifest", "runner", "selection", "tolerance", "repeats",
    "rows", "agreed", "disagreed", "verdict", "nondeterministic", "created_at", "signer",
    "signature"], {
    "convention": {"const": "opentine.reproduce-report/1"}, "experiment": STR,
    "manifest": _DIGEST, "runner": STR, "selection": _SELECTION, "tolerance": _DEC,
    "repeats": INT, "rows": {"type": "array", "items": _REROW}, "agreed": INT,
    "disagreed": INT, "verdict": {"enum": ["agree", "disagree"]},
    "nondeterministic": {"type": "array", "items": {"enum": [
        "model", "sampling", "seeds", "code_digest", "container_digest", "score"]}},
    "created_at": STR, "signer": _DIGEST, "signature": SIG})  # fmt: skip
_FINDING = closed(["level", "code", "row", "message"], {
    "level": {"enum": ["fail", "advisory"]},
    "code": {"type": "string", "pattern": "^(fail|advisory):experiment\\.[a-z-]+$"},
    "row": opt(STR), "message": STR})  # fmt: skip
_HEAD = {"schema": {"const": "tine-cli-experiment/1"}}
_SHAPES = [
    closed(["command", "schema", "experiment", "manifest", "signer", "rows", "path"], {
        **_HEAD, "command": {"const": "experiment sign"}, "experiment": STR,
        "manifest": _DIGEST, "signer": _DIGEST, "rows": INT, "path": STR}),
    closed(["command", "schema", "ok", "kind", "experiment", "manifest", "signer", "rows",
            "verdict", "findings"], {
        **_HEAD, "command": {"const": "experiment check"}, "ok": BOOL,
        "kind": {"enum": ["manifest", "reproduce-report"]}, "experiment": opt(STR),
        "manifest": opt(STR), "signer": opt(STR), "rows": INT,
        "verdict": opt({"enum": ["agree", "disagree"]}),
        "findings": {"type": "array", "items": _FINDING}}),
]  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-experiment-1": doc("tine-cli-experiment-1", "tine experiment ... --json",
        "`sign` signs an opentine.experiment-manifest/1 draft; `check` judges a manifest "
        "(result rows against their referenced signed verdicts) or a reproduce report, "
        "with `fail:experiment.*` and `advisory:experiment.*` findings.",
        {"anyOf": _SHAPES}),
    "tine-cli-reproduce-1": doc("tine-cli-reproduce-1", "tine reproduce --json",
        "A seeded sample of an experiment rerun through a runner; `report` is the signed "
        "opentine.reproduce-report/1.",
        closed(["command", "schema", "report", "path"], {
            "command": {"const": "reproduce"}, "schema": {"const": "tine-cli-reproduce/1"},
            "report": REPORT, "path": opt(STR)})),
    "opentine-experiment-manifest-1": doc("opentine-experiment-manifest-1",
        "opentine.experiment-manifest/1",
        "A signed experiment manifest: hypothesis, code/container digests, model, sampling, "
        "seeds, data commitments, compute spend, result rows referencing signed verdicts and "
        "the stated conclusion. A file convention, not an object kind.", MANIFEST),
    "opentine-reproduce-report-1": doc("opentine-reproduce-report-1",
        "opentine.reproduce-report/1",
        "A signed agreement/disagreement report for a seeded rerun sample of an experiment "
        "manifest. A file convention, not an object kind.", REPORT),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    "experiment sign": "tine-cli-experiment-1",
    "experiment check": "tine-cli-experiment-1",
    "reproduce": "tine-cli-reproduce-1",
}

__all__ = ["COMMAND_SCHEMAS", "MANIFEST", "REPORT", "SCHEMAS"]
