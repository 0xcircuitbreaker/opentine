"""JSON Schemas for the oversight queue (0.64).

``tine-cli-oversight-1`` is the ``tine oversight ... --json`` output.
``opentine-oversight-decision-1`` is the ``value`` of a decision annotation (an
existing ``annotation`` object chained by ``previous_id``); it is a claim
convention, not an object kind (docs/OVERSIGHT.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import INT, NUM, STR, closed, doc, opt

_FPR = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_ANN = {"type": "string", "pattern": "^annotation:sha256:[0-9a-f]{64}$"}
_ITEM = {"type": "string", "pattern": "^(promotion|monitor|integrity):.+$"}
_DECISION = {"enum": ["request", "approve", "reject"]}
_HEAD = {"schema": {"const": "tine-cli-oversight/1"}}
_TIER = closed(["tier", "k", "n"], {"tier": STR, "k": INT, "n": INT})
_ROUTE = closed(["source", "tier", "label"], {
    "source": {"enum": ["promotion", "integrity", "monitor", "eval"]}, "tier": STR,
    "label": STR, "metric": opt(STR), "above": opt(NUM), "below": opt(NUM),
    "actions": {"type": "array", "items": STR}})  # fmt: skip
_POLICY = closed(["status", "why", "sha256", "tiers", "routes"], {
    "status": {"enum": ["pinned", "unpinned", "absent"]}, "why": STR, "sha256": opt(STR),
    "tiers": {"type": "array", "items": _TIER},
    "routes": {"type": "array", "items": _ROUTE}})  # fmt: skip
_TALLY = closed(["tier", "k", "n", "approvals", "approvers"], {
    "tier": STR, "k": INT, "n": INT, "approvals": INT,
    "approvers": {"type": "array", "items": STR}})  # fmt: skip
_UNCOUNTED = closed(["decision", "signer", "why"], {
    "decision": _ANN, "signer": opt(STR),
    "why": {"enum": ["unsigned", "key-separation", "stale", "policy-unpinned",
                     "not-an-approver"]}})  # fmt: skip
_ROW = closed(
    ["id", "decision", "signer", "decided_at"],
    {"id": _ANN, "decision": opt(_DECISION), "signer": opt(STR), "decided_at": opt(STR)},
)
_ITEM_ROW = closed(["item", "source", "tiers", "state", "rejected_by", "uncounted",
                    "decisions"], {
    "item": _ITEM, "source": {"enum": ["promotion", "integrity", "monitor"]},
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
    closed(["command", "schema", "policy", "items"], {
        **_HEAD, "command": {"const": "oversight queue"},
        "policy": closed(["status", "why", "sha256"], {
            "status": {"enum": ["pinned", "unpinned", "absent"]}, "why": STR,
            "sha256": opt(STR)}),
        "items": {"type": "array", "items": _ITEM_ROW}}),
]  # fmt: skip
_BIND = closed(["label", "candidate", "previous", "sequence"], {
    "label": STR, "candidate": STR, "previous": opt(STR), "sequence": INT,
    "metrics": {"type": "object"}})  # fmt: skip
DECISION_VALUE = closed(
    ["convention", "item", "decision", "bind", "human", "note", "decided_at"], {
        "convention": {"const": "opentine.oversight-decision/1"}, "item": _ITEM,
        "decision": _DECISION, "bind": opt(_BIND), "human": opt(STR), "note": STR,
        "decided_at": STR})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-oversight-1": doc("tine-cli-oversight-1", "tine oversight ... --json",
        "The oversight queue. `policy`/`sign-policy` report whether `.tine/oversight.toml` "
        "is pinned by a policy-role key; `request`/`approve`/`reject` write one signed, held "
        "decision annotation (`opentine.oversight-decision/1`); `queue` lists every routed "
        "item with its k-of-n tally per tier and the decisions that do not count.",
        {"anyOf": _SHAPES}),
    "opentine-oversight-decision-1": doc("opentine-oversight-decision-1",
        "opentine.oversight-decision/1 annotation value",
        "The value of an annotation recording one oversight decision on an item's anchor "
        "blob, chained by previous_id. A claim convention, not an object kind.",
        DECISION_VALUE),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"oversight {verb}": "tine-cli-oversight-1"
    for verb in ("policy", "sign-policy", "request", "approve", "reject", "queue")
}

__all__ = ["COMMAND_SCHEMAS", "DECISION_VALUE", "SCHEMAS"]
