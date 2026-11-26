"""JSON Schemas for sealed segments and sampling audits (0.84).

``opentine-ingest-segment-1`` and ``opentine-ingest-audit-1`` are the ``value``
of an existing ``annotation``: claim conventions, not object kinds
(docs/RL-CAPTURE.md). :data:`SHAPES` are the ``tine ingest seal|audit|prove|segments
--json`` branches of ``tine-cli-ingest-1``.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, STR, TIME, closed, doc, opt

_ANN = {"type": "string", "pattern": "^annotation:sha256:[0-9a-f]{64}$"}
_STREAM = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"}
_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_DECIMAL = {"type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$"}
_HEAD = {"schema": {"const": "tine-cli-ingest/1"}}
_SEG_KEYS = ["convention", "stream", "seq", "previous", "batches", "first_index", "next_index",
             "episodes", "root", "log", "sealed_at"]  # fmt: skip
_SEG_PROPS = {
    "convention": {"const": "opentine.ingest-segment/1"}, "stream": _STREAM, "seq": INT,
    "previous": opt(_ANN), "batches": {"type": "array", "items": _ANN, "minItems": 1},
    "first_index": INT, "next_index": INT, "episodes": INT, "root": FPR,
    "log": closed(["origin", "index"], {"origin": STR, "index": INT}),
    "sealed_at": TIME}  # fmt: skip
SEGMENT_VALUE = closed(_SEG_KEYS, _SEG_PROPS)
_BOUND = closed(["method", "sample", "tolerated", "threshold", "miss_probability"], {
    "method": {"const": "hypergeometric"}, "sample": INT, "tolerated": INT, "threshold": INT,
    "miss_probability": {"type": "number", "minimum": 0, "maximum": 1}})  # fmt: skip
_CHECKPOINT = closed(["origin", "seal_index", "size", "root", "note"], {
    "origin": STR, "seal_index": INT, "size": INT, "root": _HEX, "note": STR})  # fmt: skip
_SOURCE = {
    "anyOf": [
        closed(["kind"], {"kind": {"const": "repository"}}),
        closed(["kind", "sha256"], {"kind": {"const": "file"}, "sha256": FPR}),
    ]
}
_FAILURE = closed(["position", "index", "status"], {
    "position": INT, "index": INT, "status": {"enum": ["missing", "altered"]}})  # fmt: skip
_AUDIT_KEYS = ["convention", "segment", "stream", "root", "episodes", "guarantee", "bound",
               "checkpoint", "reveal", "seed", "positions", "source", "checked", "ok", "missing",
               "altered", "failures", "verdict", "at"]  # fmt: skip
_AUDIT_PROPS = {
    "convention": {"const": "opentine.ingest-audit/1"}, "segment": _ANN, "stream": _STREAM,
    "root": FPR, "episodes": INT,
    "guarantee": closed(["confidence", "max_bad"], {"confidence": _DECIMAL, "max_bad": _DECIMAL}),
    "bound": _BOUND, "checkpoint": _CHECKPOINT,
    "reveal": {"type": "string", "pattern": "^[0-9a-f]{128}$"}, "seed": _HEX, "positions": FPR,
    "source": _SOURCE, "checked": INT, "ok": INT, "missing": INT, "altered": INT,
    "failures": {"type": "array", "items": _FAILURE, "maxItems": 1000},
    "verdict": {"enum": ["pass", "fail"]}, "at": TIME}  # fmt: skip
AUDIT_VALUE = closed(_AUDIT_KEYS, _AUDIT_PROPS)
_PROOF = closed(["segment", "root", "size", "position", "index", "leaf", "proof"], {
    "segment": _ANN, "root": FPR, "size": INT, "position": INT, "index": INT, "leaf": _HEX,
    "proof": {"type": "array", "items": _HEX, "maxItems": 64}})  # fmt: skip
_FINDING = closed(["level", "code", "record", "message"], {
    "level": {"enum": ["fail", "advisory"]}, "code": STR, "record": opt(_ANN),
    "message": STR})  # fmt: skip
_ROW = closed(["id", "seq", "episodes", "root", "audits"], {
    "id": _ANN, "seq": {"type": ["integer", "null"]}, "episodes": {"type": ["integer", "null"]},
    "root": {"type": ["string", "null"]}, "audits": {"type": "array", "items": _ANN}})  # fmt: skip
_REPORT = closed(["stream", "segments", "episodes", "roles", "ok", "findings"], {
    "stream": _STREAM, "segments": {"type": "array", "items": _ROW}, "episodes": INT,
    "roles": {"enum": ["pinned", "unpinned", "absent"]}, "ok": BOOL,
    "findings": {"type": "array", "items": _FINDING}})  # fmt: skip
SHAPES = [
    closed(["command", "schema", "segment"], {
        **_HEAD, "command": {"const": "ingest seal"},
        "segment": closed(["id", *_SEG_KEYS], {"id": _ANN, **_SEG_PROPS})}),
    closed(["command", "schema", "audit"], {
        **_HEAD, "command": {"const": "ingest audit"},
        "audit": closed(["id", *_AUDIT_KEYS], {"id": _ANN, **_AUDIT_PROPS})}),
    closed(["command", "schema", "proof"], {
        **_HEAD, "command": {"const": "ingest prove"}, "proof": _PROOF}),
    closed(["command", "schema", "report"], {
        **_HEAD, "command": {"const": "ingest segments"}, "report": _REPORT}),
]  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-ingest-segment-1": doc("opentine-ingest-segment-1",
        "opentine.ingest-segment/1 annotation value",
        "A sealed episode segment: an RFC 6962 Merkle root over the captured episodes of a "
        "run of ingest batches, signed once by a pinned runner key and committed in the op "
        "log. A claim convention on an existing annotation, not an object kind.",
        SEGMENT_VALUE),
    "opentine-ingest-audit-1": doc("opentine-ingest-audit-1",
        "opentine.ingest-audit/1 annotation value",
        "A signed sampling audit of a sealed segment: the stated guarantee, the exact "
        "hypergeometric sample size, the op log checkpoint the seed came from, and how many "
        "sampled episodes were missing or altered. A claim convention on an existing "
        "annotation, not an object kind.", AUDIT_VALUE),
}  # fmt: skip
VERBS = ("seal", "audit", "prove", "segments")

__all__ = ["AUDIT_VALUE", "SCHEMAS", "SEGMENT_VALUE", "SHAPES", "VERBS"]
