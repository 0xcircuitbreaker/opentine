"""JSON Schemas for merges (0.47, SPEC 4.19).

``opentine-merge-1`` (a signed ``opentine.merge`` attestation),
``opentine-merge-approval-1`` (a signed human approval) and
``opentine-merge-gates-1`` (a merge queue's gate policy) are the records;
``tine-cli-merge-1``, ``tine-cli-pick-1`` and ``tine-cli-merge-queue-1`` are the
``--json`` outputs. The schemas check shape; signatures, digests and fencing
are the verifier's (``opentine._merge_record``, ``opentine._merge_gates``).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, OBJ, SIG, STR, closed, doc, open_, opt

_RUN: dict[str, Any] = {"type": "string", "pattern": "^run:sha256:[0-9a-f]{64}$"}
_EVENT: dict[str, Any] = {"type": "string", "pattern": "^event:sha256:[0-9a-f]{64}$"}
_BLOB: dict[str, Any] = {"type": "string", "pattern": "^blob:sha256:[0-9a-f]{64}$"}
_NAME: dict[str, Any] = {"type": "string", "pattern": "^[A-Za-z0-9_.:/@+-]{1,256}$"}
_ID: dict[str, Any] = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"}
_WHEN: dict[str, Any] = {
    "type": "string",
    "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
}
_GATE = closed(["gate", "digest"], {"gate": {"enum": ["vsa", "eval", "approval"]}, "digest": FPR})
_CONFLICT = closed(["kind", "base", "ours", "theirs"], {
    "kind": {"enum": ["tree", "manifest"]}, "path": STR, "name": STR,
    "base": opt(STR), "ours": opt(STR), "theirs": opt(STR)})  # fmt: skip
_QUEUE = closed(["queue", "target", "gates", "head", "entries", "holder", "fencing",
                 "lease_expires_ms", "landed", "rejected", "updated_ms"], {
    "queue": _ID, "target": STR, "gates": opt({"$ref": "opentine-merge-gates-1.schema.json"}),
    "head": opt(_RUN), "holder": opt(STR), "fencing": INT, "lease_expires_ms": opt(INT),
    "updated_ms": INT,
    "entries": {"type": "array", "items": closed(["run", "by", "enqueued_ms"], {
        "run": _RUN, "by": STR, "enqueued_ms": INT})},
    "landed": {"type": "array", "items": closed(["run", "merge", "fencing", "attestation"], {
        "run": _RUN, "merge": _RUN, "fencing": INT, "attestation": opt(_BLOB)})},
    "rejected": {"type": "array", "items": closed(["run", "reason", "fencing"], {
        "run": _RUN, "reason": STR, "fencing": INT})}})  # fmt: skip
_LANDING = closed(["status", "run", "merge", "fencing", "attestation", "gates"], {
    "status": {"enum": ["landed", "rejected"]}, "run": _RUN, "merge": opt(_RUN),
    "parents": opt({"type": "array", "items": _RUN}), "fencing": INT,
    "attestation": opt(_BLOB), "gates": {"type": "array", "items": _GATE},
    "fast_forward": BOOL, "reason": STR})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-merge-1": doc("opentine-merge-1", "opentine.merge (merge_version 1)",
        "A signed merge attestation (SPEC 4.19): the merged run, its parents (ours first), "
        "the target ref and fencing token it landed under, and the digest of every gate "
        "piece that admitted it. `signature` is a tine-sig/3 block over `opentine.merge.v1:` "
        "+ JCS({body, header}).",
        closed(["kind", "merge_version", "run", "parents", "target", "fencing", "gates",
                "conflicts", "actor", "merged_at", "signature"], {
            "kind": {"const": "opentine.merge"}, "merge_version": {"const": 1}, "run": _RUN,
            "parents": {"type": "array", "items": _RUN, "minItems": 2, "maxItems": 64},
            "target": opt(_NAME), "fencing": opt(INT),
            "gates": {"type": "array", "items": _GATE, "maxItems": 256},
            "conflicts": INT, "actor": _NAME, "merged_at": _WHEN, "signature": SIG})),
    "opentine-merge-approval-1": doc("opentine-merge-approval-1",
        "opentine.merge-approval (approval_version 1)",
        "One person's signed decision on a candidate run for a target (SPEC 4.19), a merge "
        "queue's approval gate. `signature` is a tine-sig/3 block over "
        "`opentine.merge-approval.v1:` + JCS({body, header}).",
        closed(["kind", "approval_version", "run", "target", "decision", "approver",
                "approved_at", "signature"], {
            "kind": {"const": "opentine.merge-approval"}, "approval_version": {"const": 1},
            "run": _RUN, "target": _NAME, "decision": {"enum": ["approve", "reject"]},
            "approver": _NAME, "approved_at": _WHEN, "signature": SIG})),
    "opentine-merge-gates-1": doc("opentine-merge-gates-1", "opentine-merge-gates/1",
        "A merge queue's gate policy (SPEC 4.19): a pinned server VSA, a number of passing "
        "signed eval verdicts, and a number of signed approvals from listed keys.",
        closed(["format"], {
            "format": {"const": "opentine-merge-gates/1"},
            "vsa": opt(open_(["key"], {"key": STR, "levels": {"type": "array", "items": STR},
                                       "policy": STR, "resource": STR})),
            "evals": opt(open_(["min"], {"min": {"type": "integer", "minimum": 1},
                                         "signers": {"type": "array", "items": FPR}})),
            "approvals": opt(open_(["required", "keys"], {
                "required": {"type": "integer", "minimum": 1},
                "keys": {"type": "array", "items": {"type": "string",
                                                   "pattern": "^[0-9a-f]{64}$"}}}))})),
    "tine-cli-merge-1": doc("tine-cli-merge-1", "tine merge OURS THEIRS --json",
        "The merge run written, its merge event and parents, how many events both sides "
        "shared, the merged workspace tree and any conflicts (then `ok` is false, exit 1).",
        open_(["command", "ok", "run", "event", "parents", "conflicts", "status"], {
            "command": {"const": "merge"}, "ok": BOOL, "run": _RUN, "event": _EVENT,
            "parents": {"type": "array", "items": _RUN}, "base_events": INT,
            "conflicts": {"type": "array", "items": _CONFLICT},
            "status": {"enum": ["completed", "paused"]}, "tree": opt(_BLOB),
            "ref": opt(STR)})),
    "tine-cli-pick-1": doc("tine-cli-pick-1", "tine pick ONTO EVENT... --json",
        "The run written, the run it continues and each picked event's copy.",
        open_(["command", "ok", "run", "forked_from", "picked"], {
            "command": {"const": "pick"}, "ok": BOOL, "run": _RUN, "forked_from": _RUN,
            "picked": {"type": "array", "items": closed(["from", "event"], {
                "from": _EVENT, "event": _EVENT})}, "ref": opt(STR)})),
    "tine-cli-merge-queue-1": doc("tine-cli-merge-queue-1", "tine merge-queue ACTION --json",
        "Every `tine merge-queue` action: `queue` (the record's value) for init, add, claim, "
        "heartbeat and show; `result` for land (one landing) and verify (the record check); "
        "`results` for work; `record` for approve.",
        open_(["command", "action", "ok"], {
            "command": {"const": "merge-queue"},
            "action": {"enum": ["init", "add", "claim", "heartbeat", "land", "work", "show",
                                "approve", "verify"]},
            "ok": BOOL, "queue": _QUEUE, "result": OBJ, "total": INT,
            "results": {"type": "array", "items": _LANDING},
            "record": {"$ref": "opentine-merge-approval-1.schema.json"}})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {
    "merge": "tine-cli-merge-1",
    "pick": "tine-cli-pick-1",
    "merge-queue": "tine-cli-merge-queue-1",
}

#: ``kind`` value -> schema stem, for the records (they carry no tag or ``command``).
KIND_SCHEMAS: dict[str, str] = {
    "opentine.merge": "opentine-merge-1",
    "opentine.merge-approval": "opentine-merge-approval-1",
}

__all__ = ["COMMAND_SCHEMAS", "KIND_SCHEMAS", "SCHEMAS"]
