"""JSON Schemas for uplift suites, records and reports (0.73).

``tine-cli-uplift-1`` is the ``tine uplift ... --json`` output. The suite and
record claims are claim conventions on attestations and the export is a file
format; none is an object kind (docs/UPLIFT.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt

_HEAD = {"schema": {"const": "tine-cli-uplift/1"}}
_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_ID = {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,128}$"}
_MIN = {"type": "string", "pattern": "^(0|[1-9][0-9]{0,8})(\\.[0-9]{1,6})?$"}
_DEC = {"type": "string", "pattern": "^-?[0-9]+\\.[0-9]{6}$"}
_TYPE = {"enum": ["baseline", "run", "speed"]}
_COND = {"enum": ["human", "ai", "ai-assisted", "unassisted"]}
_GEN = opt({"type": "integer", "minimum": 0})
_FINDING = closed(["level", "code", "oid", "message"], {
    "level": {"enum": ["fail", "advisory"]},
    "code": {"type": "string", "pattern": "^(fail|advisory):uplift\\.[a-z-]+$"},
    "oid": STR, "message": STR})  # fmt: skip
_STATUS = {"enum": ["ok", "insufficient-data", "insufficient-lengths", "no-variation",
                    "not-converged", "no-decline"]}  # fmt: skip
_FIT_PROPS = {
    "status": _STATUS, "n": INT, "successes": INT, "lengths": INT, "intercept": opt(_DEC),
    "slope": opt(_DEC), "horizon_minutes": opt(_DEC),
    "ci": opt({"type": "array", "items": _DEC, "minItems": 2, "maxItems": 2}),
    "iterations": INT, "bootstrap_used": INT, "bootstrap_failed": INT}  # fmt: skip
_FIT = closed(list(_FIT_PROPS), _FIT_PROPS)
_TREND = closed(["generation", *_FIT_PROPS], {"generation": INT, **_FIT_PROPS})
_GROUP = closed(
    ["condition", "subject", "attempts", "successes", "success_rate", "speed_records",
     "perceived_over_measured", "fit"], {
        "condition": _COND, "subject": opt(_ID), "attempts": INT, "successes": INT,
        "success_rate": opt(_DEC), "speed_records": INT,
        "perceived_over_measured": opt(_DEC), "fit": _FIT})  # fmt: skip
_REPORT = {"ok": BOOL, "strict": BOOL, "blocking": INT, "suite": _DIGEST,
           "export_digest": _DIGEST, "seed": INT, "resamples": INT, "alpha": STR,
           "bootstrap": {"enum": ["naive", "cluster"]},
           "cluster_key": opt({"enum": ["task", "subject"]}),
           "findings": {"type": "array", "items": _FINDING}}  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "suite", "tasks", "record", "run"], {
        **_HEAD, "command": {"const": "uplift suite"}, "suite": _DIGEST, "tasks": INT,
        "record": opt(_ATT), "run": opt(STR)}),
    closed(["command", "schema", "record", "suite", "type", "task", "run"], {
        **_HEAD, "command": {"const": "uplift record"}, "record": _ATT, "suite": _DIGEST,
        "type": _TYPE, "task": _ID, "run": STR}),
    closed(["command", "schema", *_REPORT, "condition", "subject", "fit", "trend"], {
        **_HEAD, "command": {"const": "uplift horizon"}, **_REPORT, "condition": _COND,
        "subject": opt(_ID), "fit": _FIT, "trend": {"type": "array", "items": _TREND}}),
    closed(["command", "schema", *_REPORT, "a", "b", "paired_tasks", "b_over_a_minutes"], {
        **_HEAD, "command": {"const": "uplift compare"}, **_REPORT, "a": _GROUP, "b": _GROUP,
        "paired_tasks": INT, "b_over_a_minutes": opt(_DEC)}),
]  # fmt: skip
SUITE_BODY = closed(["name", "version", "scoring", "tasks"], {
    "name": STR, "version": STR, "scoring": STR,
    "tasks": {"type": "array", "minItems": 1,
              "items": closed(["id", "minutes"], {"id": _ID, "minutes": _MIN})}})  # fmt: skip
SUITE_CLAIM = closed(["convention", "digest", "suite", "at"], {
    "convention": {"const": "opentine.uplift-suite/1"}, "digest": _DIGEST,
    "suite": SUITE_BODY, "at": STR})  # fmt: skip
_ROW_PROPS = {"record": _TYPE, "task": _ID, "subject": _ID, "condition": _COND,
              "success": opt(BOOL), "minutes": opt(_MIN), "perceived_minutes": opt(_MIN),
              "generation": _GEN}  # fmt: skip
RECORD_CLAIM = closed(["convention", "suite", *_ROW_PROPS, "at"], {
    "convention": {"const": "opentine.uplift-record/1"}, "suite": _DIGEST, **_ROW_PROPS,
    "at": STR})  # fmt: skip
EXPORT = closed(["format", "suite", "definition", "records", "findings"], {
    "format": {"const": "opentine-uplift-export/1"}, "suite": _DIGEST, "definition": SUITE_BODY,
    "records": {"type": "array", "items": closed(["oid", *_ROW_PROPS],
                                                 {"oid": _ATT, **_ROW_PROPS})},
    "findings": {"type": "array", "items": _FINDING}})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-uplift-1": doc("tine-cli-uplift-1", "tine uplift ... --json",
        "Uplift and capability trends. `suite` and `record` write signed, held claims; "
        "`horizon` reports the 50%-success time horizon (logistic fit on log2 task length, "
        "seeded bootstrap interval; `bootstrap` names the method, `cluster` resampling "
        "clusters named by `cluster_key` and then points inside them) with a per-generation "
        "trend; `compare` sets two groups side by side. Reports are recomputable byte for "
        "byte from the export.",
        {"anyOf": _SHAPES}),
    "opentine-uplift-suite-1": doc("opentine-uplift-suite-1", "opentine.uplift-suite/1 claim",
        "The claim of an attestation recording a versioned task suite (task list, lengths in "
        "minutes, scoring) and its digest. A claim convention, not an object kind.",
        SUITE_CLAIM),
    "opentine-uplift-record-1": doc("opentine-uplift-record-1", "opentine.uplift-record/1 claim",
        "The claim of an attestation recording one human baseline, AI, AI-assisted or "
        "unassisted attempt, or one perceived-vs-measured speed record, against a suite. "
        "A claim convention, not an object kind.", RECORD_CLAIM),
    "opentine-uplift-export-1": doc("opentine-uplift-export-1", "opentine-uplift-export/1 file",
        "Every counted record of one suite in a fixed order; `tine uplift horizon|compare "
        "--from FILE` recompute their reports from it byte for byte. A file format, not an "
        "object kind.", EXPORT),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"uplift {verb}": "tine-cli-uplift-1" for verb in ("suite", "record", "horizon", "compare")
}

__all__ = ["COMMAND_SCHEMAS", "EXPORT", "RECORD_CLAIM", "SCHEMAS", "SUITE_CLAIM"]
