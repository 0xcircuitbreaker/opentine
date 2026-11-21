"""JSON Schema for ``tine policy check|list|show`` and the policy file and admission claim (0.74).

``opentine-policy-1`` (a policy file) and ``opentine-policy-admission-1`` (the
claim of an existing attestation) are conventions, not object kinds
(docs/POLICY.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, STR, closed, doc, opt

_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_HEAD = {"schema": {"const": "tine-cli-policy/1"}}
_ATT = {"type": "string", "pattern": "^attestation:"}
_OUTCOME = {"enum": ["true", "false", "error"]}
_EFFECT = {"enum": ["require", "advisory"]}
_CODE = opt({"type": "string", "pattern": "^policy\\.[a-z-]+$"})
_RULE_RESULT = closed(["id", "effect", "outcome", "code", "message"], {
    "id": STR, "effect": _EFFECT, "outcome": _OUTCOME, "code": _CODE,
    "message": opt(STR)})  # fmt: skip
_POLICY_REF = closed(["name", "digest"], {"name": STR, "digest": _DIGEST})
ADMISSION = closed(["convention", "verificationResult", "decision", "policy", "subject",
                    "input_digest", "rules", "at"], {
    "convention": {"const": "opentine.policy-admission/1"},
    "verificationResult": {"enum": ["PASSED", "FAILED"]},
    "decision": {"enum": ["allow", "deny"]}, "policy": _POLICY_REF, "subject": STR,
    "input_digest": _DIGEST,
    "rules": {"type": "array", "items": closed(["id", "effect", "outcome", "code"], {
        "id": STR, "effect": _EFFECT, "outcome": _OUTCOME, "code": _CODE})},
    "at": STR})  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "policy", "subject", "input_digest", "decision", "rules",
            "recorded"], {
        **_HEAD, "command": {"const": "policy check"}, "policy": _POLICY_REF, "subject": STR,
        "input_digest": _DIGEST, "decision": {"enum": ["allow", "deny"]},
        "rules": {"type": "array", "items": _RULE_RESULT}, "recorded": opt(_ATT),
        "input": {}}),
    closed(["command", "schema", "policies"], {
        **_HEAD, "command": {"const": "policy list"},
        "policies": {"type": "array", "items": closed(["name", "digest", "description"], {
            "name": STR, "digest": _DIGEST, "description": STR})}}),
    closed(["command", "schema", "subject", "records"], {
        **_HEAD, "command": {"const": "policy show"}, "subject": STR,
        "records": {"type": "array", "items": closed(["oid", "signer", "signed", "roles",
                                                      "claim"], {
            "oid": STR, "signer": opt(STR), "signed": BOOL,
            "roles": {"type": "array", "items": STR}, "claim": {}})}}),
]  # fmt: skip
_RULE = closed(["id", "expr", "effect"], {
    "id": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,64}$"},
    "expr": {"type": "string", "maxLength": 4096}, "effect": _EFFECT,
    "description": STR})  # fmt: skip
SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-policy-1": doc("tine-cli-policy-1", "tine policy check|list|show --json",
        "A policy decision over the signed records of a run (per-rule outcomes, policy and "
        "input digests, the admission record when signed), the standard policies, or the "
        "held admission records of a run.", {"anyOf": _SHAPES}),
    "opentine-policy-1": doc("opentine-policy-1", "opentine.policy/1 policy file",
        "Declarative admission rules in a bounded CEL subset (docs/POLICY.md). A file "
        "convention, not an object kind.",
        closed(["schema", "name", "rules"], {
            "schema": {"const": "opentine.policy/1"}, "name": STR, "description": STR,
            "params": {"type": "object"},
            "rules": {"type": "array", "items": _RULE, "minItems": 1, "maxItems": 64}})),
    "opentine-policy-admission-1": doc("opentine-policy-admission-1",
        "opentine.policy-admission/1 claim",
        "A signed admission decision (a verification summary) on a run, held and never "
        "released. A claim convention on an existing attestation, not an object kind.",
        ADMISSION),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {f"policy {v}": "tine-cli-policy-1"
                                   for v in ("check", "list", "show")}  # fmt: skip

__all__ = ["ADMISSION", "COMMAND_SCHEMAS", "SCHEMAS"]
