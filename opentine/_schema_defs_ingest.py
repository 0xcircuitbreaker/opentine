"""JSON Schemas for batched streaming ingest (0.77).

``tine-cli-ingest-1`` is the ``tine ingest ... --json`` output.
``opentine-ingest-policy-1`` and ``opentine-ingest-batch-1`` are the ``value``
of an existing ``annotation`` on a stream's anchor blob: claim conventions,
not object kinds (docs/INGEST.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, STR, TIME, closed, doc, opt
from opentine._schema_defs_ingest_audit import SCHEMAS as _AUDIT_SCHEMAS
from opentine._schema_defs_ingest_audit import SHAPES as _AUDIT_SHAPES
from opentine._schema_defs_ingest_audit import VERBS as _AUDIT_VERBS

_ANN = {"type": "string", "pattern": "^annotation:sha256:[0-9a-f]{64}$"}
_STREAM = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"}
_KINDS = {"type": "array", "items": STR, "maxItems": 256}
_HEAD = {"schema": {"const": "tine-cli-ingest/1"}}
_POLICY_KEYS = ["convention", "stream", "capture", "drop", "rate", "seed_source", "seed",
                "redact", "issued_at"]  # fmt: skip
_POLICY_PROPS = {
    "convention": {"const": "opentine.ingest-policy/1"}, "stream": _STREAM, "capture": _KINDS,
    "drop": _KINDS, "rate": {"type": "number", "minimum": 0, "maximum": 1},
    "seed_source": {"enum": ["operator", "random"]},
    "seed": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "redact": BOOL,
    "issued_at": TIME}  # fmt: skip
POLICY_VALUE = closed(_POLICY_KEYS, _POLICY_PROPS)
_DROPPED_BY = closed(["kind", "rate"], {"kind": INT, "rate": INT})
_BATCH_KEYS = ["convention", "stream", "seq", "previous", "policy", "policy_digest",
               "first_index", "next_index", "received", "captured", "dropped", "dropped_by",
               "input_sha256", "at"]  # fmt: skip
_BATCH_PROPS = {
    "convention": {"const": "opentine.ingest-batch/1"}, "stream": _STREAM, "seq": INT,
    "previous": opt(_ANN), "policy": _ANN, "policy_digest": FPR, "first_index": INT,
    "next_index": INT, "received": INT, "captured": INT, "dropped": INT,
    "dropped_by": _DROPPED_BY, "input_sha256": FPR, "at": TIME}  # fmt: skip
_LINES = {"type": "string", "description": 'JSON Lines: {"e": EVENT, "i": INDEX, "k": KIND}'}
BATCH_VALUE = closed([*_BATCH_KEYS, "events"], {**_BATCH_PROPS, "events": _LINES})
_FINDING = closed(["level", "code", "batch", "message"], {
    "level": {"enum": ["fail", "advisory"]}, "code": STR, "batch": opt(_ANN),
    "message": STR})  # fmt: skip
_REPORT = closed(["stream", "head", "batches", "received", "captured", "dropped", "policies",
                  "roles", "ok", "findings"], {
    "stream": _STREAM, "head": opt(_ANN), "batches": INT, "received": INT, "captured": INT,
    "dropped": INT, "policies": {"type": "array", "items": _ANN},
    "roles": {"enum": ["pinned", "unpinned", "absent"]}, "ok": BOOL,
    "findings": {"type": "array", "items": _FINDING}})  # fmt: skip
_TENANT = closed(["tenant", "packs", "objects", "bad"], {
    "tenant": STR, "packs": INT, "objects": INT,
    "bad": {"type": "array", "items": STR}})  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "batch"], {
        **_HEAD, "command": {"const": "ingest --batch"},
        "batch": closed(["id", *_BATCH_KEYS], {"id": _ANN, **_BATCH_PROPS})}),
    closed(["command", "schema", "policy"], {
        **_HEAD, "command": {"const": "ingest policy"},
        "policy": closed(["id", "digest", *_POLICY_KEYS],
                         {"id": _ANN, "digest": FPR, **_POLICY_PROPS})}),
    closed(["command", "schema", "report"], {
        **_HEAD, "command": {"const": "ingest verify"}, "report": _REPORT}),
    closed(["command", "schema", "packs"], {
        **_HEAD, "command": {"const": "ingest packs"},
        "packs": {"type": "array", "items": _TENANT}}),
    *_AUDIT_SHAPES,  # 0.84: seal, audit, prove, segments
]  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-ingest-1": doc("tine-cli-ingest-1", "tine ingest ... --json",
        "Batched streaming ingest. `ingest policy` signs and holds a sampling policy; "
        "`ingest --batch` samples, signs and chains one batch; `ingest verify` checks the "
        "chain, counts and policy; `ingest packs` re-reads a tine serve pack store; "
        "`ingest seal`, `audit`, `prove` and `segments` seal Merkle-rooted episode segments "
        "and audit them by sampling (0.84).",
        {"anyOf": _SHAPES}),
    "opentine-ingest-policy-1": doc("opentine-ingest-policy-1",
        "opentine.ingest-policy/1 annotation value",
        "A signed sampling policy for one ingest stream: what is captured or dropped, the "
        "rate and the seed. A claim convention on an existing annotation, not an object "
        "kind.", POLICY_VALUE),
    "opentine-ingest-batch-1": doc("opentine-ingest-batch-1",
        "opentine.ingest-batch/1 annotation value",
        "One signed ingest batch: counts captured and dropped, the policy digest, the "
        "chain link to the previous batch and the captured events. A claim convention on "
        "an existing annotation, not an object kind.", BATCH_VALUE),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"ingest {verb}": "tine-cli-ingest-1"
    for verb in ("--batch", "policy", "verify", "packs", *_AUDIT_VERBS)
}
SCHEMAS.update(_AUDIT_SCHEMAS)

__all__ = ["BATCH_VALUE", "COMMAND_SCHEMAS", "POLICY_VALUE", "SCHEMAS"]
