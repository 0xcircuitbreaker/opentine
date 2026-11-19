"""JSON Schemas for the oversight queue (0.64).

``tine-cli-oversight-1`` is the ``tine oversight ... --json`` output.
``opentine-oversight-decision-1`` is the ``value`` of a decision annotation (an
existing ``annotation`` object chained by ``previous_id``); it is a claim
convention, not an object kind (docs/OVERSIGHT.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, NUM, STR, closed, doc, opt

_FPR = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_ANN = {"type": "string", "pattern": "^annotation:sha256:[0-9a-f]{64}$"}
_ITEM = {"type": "string", "pattern": "^(promotion|monitor|integrity):.+$"}
_DECISION = {"enum": ["request", "approve", "reject"]}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_STATES = ("pending", "approved", "rejected", "unrouted")
_HEAD = {"schema": {"const": "tine-cli-oversight/1"}}
_TIER = closed(["tier", "k", "n"], {"tier": STR, "k": INT, "n": INT})
_ROUTE = closed(["source", "tier", "label"], {
    "source": {"enum": ["promotion", "integrity", "monitor", "eval"]}, "tier": STR,
    "label": STR, "metric": opt(STR), "above": opt(NUM), "below": opt(NUM),
    "actions": {"type": "array", "items": STR}})  # fmt: skip
_POLICY = closed(["status", "why", "floors", "sha256", "tiers", "routes"], {
    "status": {"enum": ["pinned", "unpinned", "absent"]}, "why": STR, "sha256": opt(STR),
    "floors": BOOL,
    "tiers": {"type": "array", "items": _TIER},
    "routes": {"type": "array", "items": _ROUTE}})  # fmt: skip
_TALLY = closed(["tier", "k", "n", "approvals", "approvers"], {
    "tier": STR, "k": INT, "n": INT, "approvals": INT,
    "approvers": {"type": "array", "items": STR}})  # fmt: skip
_UNCOUNTED = closed(["decision", "signer", "why"], {
    "decision": _ANN, "signer": opt(STR),
    "why": {"enum": ["unsigned", "key-separation", "stale", "policy-unpinned",
                     "not-an-approver"]}})  # fmt: skip
_VIEWED = closed(["evidence", "at"], {"evidence": {"type": "array", "items": STR},
                                        "at": STR})  # fmt: skip
_ROW = closed(["id", "decision", "signer", "decided_at", "counted", "viewed"], {
    "id": _ANN, "decision": opt(_DECISION), "signer": opt(STR), "decided_at": opt(STR),
    "counted": BOOL, "viewed": opt(_VIEWED)})  # fmt: skip
_ITEM_ROW = closed(["item", "source", "opened_at", "tiers", "state", "rejected_by",
                    "uncounted", "decisions"], {
    "item": _ITEM, "source": {"enum": ["promotion", "integrity", "monitor"]},
    "opened_at": opt(STR),
    "tiers": {"type": "array", "items": _TALLY},
    "state": {"enum": ["pending", "approved", "rejected", "unrouted"]},
    "rejected_by": {"type": "array", "items": STR},
    "uncounted": {"type": "array", "items": _UNCOUNTED},
    "decisions": {"type": "array", "items": _ROW}})  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "policy"], {
        **_HEAD, "command": {"enum": ["oversight policy", "oversight sign-policy"]},
        "policy": _POLICY}),
    closed(["command", "schema", "decisions"], {
        **_HEAD, "command": {"enum": ["oversight request", "oversight approve",
                                      "oversight reject"]},
        "decisions": {"type": "array", "items": closed(
            ["decision", "item", "action", "signer"], {
                "decision": _ANN, "item": _ITEM, "action": _DECISION, "signer": _FPR})}}),
    closed(["command", "schema", "policy", "counts", "items", "digest"], {
        **_HEAD, "command": {"const": "oversight queue"},
        "policy": closed(["status", "why", "sha256", "floors"], {
            "status": {"enum": ["pinned", "unpinned", "absent"]}, "why": STR,
            "sha256": opt(STR), "floors": BOOL}),
        "counts": closed(list(_STATES), {s: INT for s in _STATES}),
        "items": {"type": "array", "items": _ITEM_ROW}, "digest": _DIGEST}),
    closed(["command", "schema", "advisory", "min_review_seconds", "queue", "decisions",
            "approvals", "rubber_stamps", "rubber_stamp_rate", "median_seconds_to_decision",
            "max_seconds_to_decision", "pending", "oldest_pending_seconds", "approvers"], {
        **_HEAD, "command": {"const": "oversight fatigue"}, "advisory": {"const": True},
        "min_review_seconds": INT, "queue": _DIGEST, "decisions": INT, "approvals": INT,
        "rubber_stamps": INT, "rubber_stamp_rate": opt(NUM),
        "median_seconds_to_decision": opt(NUM), "max_seconds_to_decision": opt(NUM),
        "pending": INT, "oldest_pending_seconds": opt(NUM),
        "approvers": {"type": "array", "items": closed(
            ["signer", "approvals", "rejections", "rubber_stamps",
             "median_seconds_to_decision"], {
                "signer": STR, "approvals": INT, "rejections": INT, "rubber_stamps": INT,
                "median_seconds_to_decision": opt(NUM)})}}),
]  # fmt: skip
_BIND = closed(["label", "candidate", "previous", "sequence"], {
    "label": STR, "candidate": STR, "previous": opt(STR), "sequence": INT,
    "metrics": {"type": "object"}})  # fmt: skip
DECISION_VALUE = closed(
    ["convention", "item", "decision", "bind", "human", "note", "decided_at"], {
        "convention": {"const": "opentine.oversight-decision/1"}, "item": _ITEM,
        "decision": _DECISION, "bind": opt(_BIND), "human": opt(STR), "note": STR,
        "decided_at": STR, "viewed": _VIEWED})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-oversight-1": doc("tine-cli-oversight-1", "tine oversight ... --json",
        "The oversight queue. `policy`/`sign-policy` report whether `.tine/oversight.toml` "
        "is pinned by a policy-role key; `request`/`approve`/`reject` write one signed, held "
        "decision annotation (`opentine.oversight-decision/1`); `queue` lists every routed "
        "item with its k-of-n tally per tier and the decisions that do not count, plus a "
        "`digest` that `tine ui --repo` serves unchanged; `fatigue` is the advisory "
        "approver-fatigue report (time to decision from record timestamps).",
        {"anyOf": _SHAPES}),
    "opentine-oversight-decision-1": doc("opentine-oversight-decision-1",
        "opentine.oversight-decision/1 annotation value",
        "The value of an annotation recording one oversight decision on an item's anchor "
        "blob, chained by previous_id. A claim convention, not an object kind.",
        DECISION_VALUE),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"oversight {verb}": "tine-cli-oversight-1"
    for verb in ("policy", "sign-policy", "request", "approve", "reject", "queue", "fatigue")
}

__all__ = ["COMMAND_SCHEMAS", "DECISION_VALUE", "SCHEMAS"]
