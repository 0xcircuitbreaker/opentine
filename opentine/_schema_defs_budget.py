"""JSON Schemas for budgets (0.69).

``tine-cli-budget-1`` is the ``tine budget ... --json`` output.
``opentine-budget-policy-1`` is a signed budget policy file and
``opentine-budget-ledger-1`` the ``value`` of a ledger annotation (an existing
``annotation`` object chained by ``previous_id``): claim conventions, not object
kinds (docs/BUDGETS.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, NUM, OBJ, SIG, STR, TIME, closed, doc, opt

_ANN = {"type": "string", "pattern": "^annotation:sha256:[0-9a-f]{64}$"}
_SUBJECT = {"type": "string", "pattern": "^(loop|agent):[a-z0-9][a-z0-9._-]{0,63}$"}
_LIMITS = ("tokens", "gpu_hours", "wall_clock_s", "egress_bytes", "money_usd")
_HEAD = {"schema": {"const": "tine-cli-budget/1"}}
_LIMIT_MAP = closed(list(_LIMITS), {n: opt(NUM) for n in _LIMITS})
_FINDING = closed(["level", "code", "entry", "message"], {
    "level": {"enum": ["fail", "advisory"]}, "code": STR, "entry": opt(_ANN),
    "message": STR})  # fmt: skip
_TOTALS = closed([*_LIMITS, "input_tokens", "output_tokens", "runs"], {
    **{n: NUM for n in _LIMITS}, "input_tokens": INT, "output_tokens": INT,
    "runs": INT})  # fmt: skip
_POLICY = closed(["schema", "subject", "serial", "limits", "on_limit", "issued_at", "sha256",
                  "signer", "entry"], {
    "schema": {"const": "opentine-budget-policy/1"}, "subject": _SUBJECT, "serial": INT,
    "limits": _LIMIT_MAP, "on_limit": {"enum": ["deny", "escalate"]}, "issued_at": STR,
    "sha256": FPR, "signer": opt(FPR), "entry": _ANN})  # fmt: skip
_STATUS = closed(["subject", "roles", "policy", "totals", "remaining", "over", "decision",
                  "entries", "head", "findings"], {
    "subject": _SUBJECT, "roles": {"enum": ["pinned", "unpinned", "absent"]},
    "policy": opt(_POLICY), "totals": _TOTALS, "remaining": _LIMIT_MAP,
    "over": {"type": "array", "items": {"enum": list(_LIMITS)}},
    "decision": {"enum": ["allow", "deny", "escalate"]}, "entries": INT, "head": opt(_ANN),
    "findings": {"type": "array", "items": _FINDING}})  # fmt: skip
_ANNS = {"type": "array", "items": _ANN}
_ROW = closed(["id", "previous", "signer", "signed", "entry", "at"], {
    "id": _ANN, "previous": opt(_ANN), "signer": opt(STR), "signed": BOOL,
    "entry": opt(STR), "at": opt(STR), "run": opt(STR), "money_usd": opt(NUM),
    "tokens": opt(NUM), "code": opt(STR), "about": opt(STR)})  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "policy"], {
        **_HEAD, "command": {"const": "budget sign-policy"},
        "policy": closed(["subject", "serial", "sha256", "signer"], {
            "subject": _SUBJECT, "serial": INT, "sha256": FPR, "signer": opt(FPR)})}),
    closed(["command", "schema", "entry", "accepted", "flags", "status"], {
        **_HEAD, "command": {"const": "budget apply"}, "entry": _ANN, "accepted": BOOL,
        "flags": _ANNS, "status": _STATUS}),
    closed(["command", "schema", "entries", "status"], {
        **_HEAD, "command": {"const": "budget record"}, "entries": _ANNS, "status": _STATUS}),
    closed(["command", "schema", "entries", "totals"], {
        **_HEAD, "command": {"const": "budget ledger"},
        "entries": {"type": "array", "items": _ROW}, "totals": _TOTALS}),
    closed(["command", "schema", "status", "flags"], {
        **_HEAD, "command": {"enum": ["budget status", "budget check"]}, "status": _STATUS,
        "flags": _ANNS}),
]  # fmt: skip
POLICY_DOC = closed(["schema", "subject", "serial", "limits", "on_limit", "issued_at",
                     "signature"], {
    "schema": {"const": "opentine-budget-policy/1"}, "subject": _SUBJECT, "serial": INT,
    "limits": {"type": "object", "additionalProperties": False,
               "properties": {n: opt(NUM) for n in _LIMITS}},
    "on_limit": {"enum": ["deny", "escalate"]}, "issued_at": TIME,
    "signature": SIG})  # fmt: skip
LEDGER_VALUE = closed(["convention", "subject", "entry", "at", "at_ms"], {
    "convention": {"const": "opentine.budget-ledger/1"}, "subject": _SUBJECT,
    "entry": {"enum": ["spend", "policy", "flag"]}, "at": TIME, "at_ms": INT,
    "run": STR, "cost": OBJ, "gpu_hours": NUM, "egress_bytes": INT,
    "policy": OBJ, "code": STR, "detail": STR, "about": opt(_ANN)})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-budget-1": doc("tine-cli-budget-1", "tine budget ... --json",
        "Budgets for a loop or agent. `sign-policy` writes a signed "
        "`opentine-budget-policy/1`; `apply` and `record` append signed, held ledger "
        "entries (`opentine.budget-ledger/1`); `status`, `check` and `ledger` fold the "
        "ledger into the policy in force, totals, findings and the next-action decision.",
        {"anyOf": _SHAPES}),
    "opentine-budget-policy-1": doc("opentine-budget-policy-1", "opentine-budget-policy/1",
        "A signed budget policy file (tokens, GPU-hours, wall clock, egress bytes, money) "
        "for one subject. A file convention, not an object kind.", POLICY_DOC),
    "opentine-budget-ledger-1": doc("opentine-budget-ledger-1",
        "opentine.budget-ledger/1 annotation value",
        "The value of an annotation recording one budget-ledger entry (spend, policy or "
        "flag) on the subject's anchor blob, chained by previous_id. A claim convention, "
        "not an object kind.", LEDGER_VALUE),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"budget {verb}": "tine-cli-budget-1"
    for verb in ("sign-policy", "apply", "record", "status", "ledger", "check")
}

__all__ = ["COMMAND_SCHEMAS", "LEDGER_VALUE", "POLICY_DOC", "SCHEMAS"]
