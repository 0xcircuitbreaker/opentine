"""JSON Schema shapes for ``tine monitor run|heartbeat|coverage|validate|suspicion --json``.

Joined into ``tine-cli-monitor-1`` by :mod:`opentine._schema_defs_monitor`.
Coverage records, heartbeats and operating points are existing object kinds
(annotations and attestations) under the claim conventions
``opentine.monitor-coverage/1``, ``opentine.monitor-heartbeat/1`` and
``opentine.monitor-operating-point/1``, published here as claim shapes.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, NUM, STR, closed, doc, opt

_HEAD = {"schema": {"const": "tine-cli-monitor/1"}}
_ANN = {"type": "string", "pattern": "^annotation:sha256:[0-9a-f]{64}$"}
_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_OUTCOMES = ("allow", "flag", "resample", "defer", "block", "error")
_IDENT = closed(["id", "kind", "config_digest"], {
    "id": STR, "kind": {"enum": ["rule", "command", "http", "probe"]},
    "config_digest": _DIGEST})  # fmt: skip
_COUNT_MAP = {"type": "object", "additionalProperties": INT}
_LATENCY = closed(["slo_ms", "p95_ms", "max_ms", "met"], {
    "slo_ms": INT, "p95_ms": INT, "max_ms": INT, "met": BOOL})  # fmt: skip
_COVERAGE_KEYS = ["convention", "monitor", "stream", "seq", "previous", "batch", "batch_seq",
                  "first_index", "next_index", "evaluated", "by_action", "by_category",
                  "threshold", "latency", "events_sha256", "at"]  # fmt: skip
_COVERAGE_PROPS = {
    "convention": {"const": "opentine.monitor-coverage/1"}, "monitor": _IDENT, "stream": STR,
    "seq": INT, "previous": opt(_ANN), "batch": _ANN, "batch_seq": INT, "first_index": INT,
    "next_index": INT, "evaluated": INT,
    "by_action": closed(list(_OUTCOMES), dict.fromkeys(_OUTCOMES, INT)),
    "by_category": _COUNT_MAP, "threshold": NUM, "latency": _LATENCY, "events_sha256": _DIGEST,
    "at": STR}  # fmt: skip
_RECORD = closed(["id", *_COVERAGE_KEYS], {"id": _ANN, **_COVERAGE_PROPS})
_BOUND = opt(closed(["head", "seq", "at"], {"head": _ANN, "seq": INT, "at": STR}))
_HEARTBEAT_KEYS = ["convention", "monitor", "stream", "seq", "previous", "interval_s", "ingest",
                   "ledger", "at"]  # fmt: skip
_HEARTBEAT_PROPS = {
    "convention": {"const": "opentine.monitor-heartbeat/1"}, "monitor": _IDENT, "stream": STR,
    "seq": INT, "previous": opt(_ANN), "interval_s": INT, "ingest": _BOUND,
    "ledger": opt(_ANN), "at": STR}  # fmt: skip
_INTERVAL = {"type": "array", "items": NUM, "minItems": 2, "maxItems": 2}
_RATE = closed(["value", "wilson", "clopper_pearson"], {
    "value": opt(NUM), "wilson": _INTERVAL, "clopper_pearson": _INTERVAL})  # fmt: skip
_POINT_KEYS = ["convention", "monitor", "threshold", "labelled", "counts", "confidence", "tpr",
               "fpr", "at"]  # fmt: skip
_POINT_PROPS = {
    "convention": {"const": "opentine.monitor-operating-point/1"}, "monitor": _IDENT,
    "threshold": NUM,
    "labelled": closed(["sha256", "attacks", "benign"], {
        "sha256": _DIGEST, "attacks": INT, "benign": INT}),
    "counts": closed(["tp", "fn", "fp", "tn", "errors"], dict.fromkeys(
        ("tp", "fn", "fp", "tn", "errors"), INT)),
    "confidence": NUM, "tpr": _RATE, "fpr": _RATE, "at": STR}  # fmt: skip
_FINDING = closed(["level", "code", "record", "message"], {
    "level": {"enum": ["fail", "advisory"]},
    "code": {"type": "string", "pattern": "^(fail|advisory):monitor\\.[a-z-]+$"},
    "record": opt(STR), "message": STR})  # fmt: skip
_WINDOW = closed(["from", "to"], {"from": opt(INT), "to": INT})
_BEATS = closed(["heartbeats", "last_ms", "stale_windows"], {
    "heartbeats": INT, "last_ms": opt(INT),
    "stale_windows": {"type": "array", "items": _WINDOW}})  # fmt: skip
_COUNTS = closed(["batches", "evaluated", "verdicts", "heartbeats"], dict.fromkeys(
    ("batches", "evaluated", "verdicts", "heartbeats"), INT))  # fmt: skip
_SUBJECT = closed(["subject", "events", "sum", "near", "failures"], {
    "subject": STR, "events": INT, "sum": NUM, "near": INT, "failures": INT})  # fmt: skip
_FLAG = closed(["level", "code", "subject", "record", "value"], {
    "level": {"const": "advisory"},
    "code": {"enum": ["advisory:monitor.cumulative-suspicion",
                      "advisory:monitor.doom-loop-near-threshold",
                      "advisory:monitor.doom-loop-repeated-failure"]},
    "subject": STR, "record": _ANN, "value": NUM})  # fmt: skip
LEDGER_SHAPES: list[dict[str, Any]] = [
    closed(["command", "schema", "records", "counts"], {
        **_HEAD, "command": {"const": "monitor run"},
        "records": {"type": "array", "items": _RECORD}, "counts": _COUNTS}),
    closed(["command", "schema", "heartbeat"], {
        **_HEAD, "command": {"const": "monitor heartbeat"},
        "heartbeat": closed(["id", *_HEARTBEAT_KEYS], {"id": _ANN, **_HEARTBEAT_PROPS})}),
    closed(["command", "schema", "stream", "monitor", "captured", "evaluated", "covered",
            "percent", "counts_as_coverage", "operating_point", "records", "gaps",
            "heartbeats", "findings", "profile", "ok", "strict", "blocking"], {
        **_HEAD, "command": {"const": "monitor coverage"}, "stream": STR, "monitor": _IDENT,
        "captured": INT, "evaluated": INT,
        "covered": {"type": "string", "pattern": "^[0-9]+/[0-9]+$"},
        "percent": opt({"type": "string", "pattern": "^[0-9]+\\.[0-9]{4}$"}),
        "counts_as_coverage": BOOL, "operating_point": opt(_ATT), "records": INT,
        "gaps": {"type": "array", "items": {"type": "array", "items": INT}},
        "heartbeats": _BEATS, "findings": {"type": "array", "items": _FINDING},
        "profile": {"enum": ["default", "rsi"]}, "ok": BOOL, "strict": BOOL,
        "blocking": INT}),
    closed(["command", "schema", "record", "claim"], {
        **_HEAD, "command": {"const": "monitor validate"}, "record": _ATT,
        "claim": closed(_POINT_KEYS, _POINT_PROPS)}),
    closed(["command", "schema", "subjects", "flags", "ok"], {
        **_HEAD, "command": {"const": "monitor suspicion"},
        "subjects": {"type": "array", "items": _SUBJECT},
        "flags": {"type": "array", "items": _FLAG}, "ok": BOOL}),
]  # fmt: skip
LEDGER_COMMANDS = tuple(f"monitor {v}" for v in ("run", "heartbeat", "coverage", "validate",
                                                  "suspicion"))  # fmt: skip
LEDGER_DESCRIPTION = (
    " `run` evaluates an ingest stream and writes coverage records "
    "(`opentine.monitor-coverage/1`); `heartbeat` signs one heartbeat "
    "(`opentine.monitor-heartbeat/1`); `coverage` reports the proven fraction of captured "
    "events a monitor evaluated; `validate` signs an operating point "
    "(`opentine.monitor-operating-point/1`); `suspicion` lists cumulative-suspicion and "
    "doom-loop flags."
)
SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-monitor-coverage-1": doc("opentine-monitor-coverage-1",
        "opentine.monitor-coverage/1 claim",
        "The value of an annotation recording which captured events of one ingest batch a "
        "monitor evaluated. A claim convention, not an object kind.",
        closed([*_COVERAGE_KEYS, "events"], {**_COVERAGE_PROPS, "events": STR})),
    "opentine-monitor-heartbeat-1": doc("opentine-monitor-heartbeat-1",
        "opentine.monitor-heartbeat/1 claim",
        "The value of an annotation proving a monitor was alive, bound to the ingest head.",
        closed(_HEARTBEAT_KEYS, _HEARTBEAT_PROPS)),
    "opentine-monitor-operating-point-1": doc("opentine-monitor-operating-point-1",
        "opentine.monitor-operating-point/1 claim",
        "The claim of an attestation recording a monitor's validated operating point.",
        closed(_POINT_KEYS, _POINT_PROPS)),
}  # fmt: skip

__all__ = ["LEDGER_COMMANDS", "LEDGER_DESCRIPTION", "LEDGER_SHAPES", "SCHEMAS"]
