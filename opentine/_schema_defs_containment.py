"""JSON Schemas for containment evidence (0.69).

``tine-cli-containment-1`` is the ``tine containment ... --json`` output. The
sandbox policy and the containment finding are claims on attestations (an
existing object kind), published as ``opentine-sandbox-policy-1`` and
``opentine-containment-finding-1``: claim conventions, not object kinds
(docs/CONTAINMENT.md). Budgets are ``tine budget`` (docs/BUDGETS.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt

_HEAD = {"schema": {"const": "tine-cli-containment/1"}}
_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_STATE = {"type": "string", "pattern": "^(verified|unverified: .+)$"}
_CATEGORY = {"enum": ["egress", "credential-access", "self-replication", "unmonitored-process",
                      "persistence", "limit-edit"]}  # fmt: skip
POLICY = closed(["network_allowlist", "mounts", "privileges", "image_digest", "seccomp_digest"], {
    "network_allowlist": {"type": "array", "items": STR},
    "mounts": {"type": "array", "items": closed(["path", "mode"], {
        "path": STR, "mode": {"enum": ["ro", "rw"]}})},
    "privileges": {"type": "array", "items": STR}, "image_digest": _DIGEST,
    "seccomp_digest": opt(_DIGEST)})  # fmt: skip
_FINDING = closed(["code", "category", "step", "detail", "evidence_digest"], {
    "code": {"type": "string", "pattern": "^advisory:containment\\.[a-z-]+$"},
    "category": _CATEGORY, "step": INT, "detail": STR, "evidence_digest": _DIGEST})  # fmt: skip
_CHECK = closed(["code", "record", "message"], {
    "code": {"enum": ["fail:sandbox-policy-mismatch", "advisory:containment.runner-unpinned"]},
    "record": opt(_ATT), "message": STR})  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "run", "record", "policy_digest"], {
        **_HEAD, "command": {"const": "containment record"}, "run": STR, "record": _ATT,
        "policy_digest": _DIGEST}),
    closed(["command", "schema", "ok", "strict", "run", "declared", "policies", "findings"], {
        **_HEAD, "command": {"const": "containment check"}, "ok": BOOL, "strict": BOOL,
        "run": STR, "declared": opt(_DIGEST),
        "policies": {"type": "array", "items": closed(
            ["record", "signer", "verification", "policy_digest"], {
                "record": _ATT, "signer": opt(STR), "verification": _STATE,
                "policy_digest": opt(STR)})},
        "findings": {"type": "array", "items": _CHECK}}),
    closed(["command", "schema", "ok", "strict", "run", "findings", "recorded"], {
        **_HEAD, "command": {"const": "containment scan"}, "ok": BOOL, "strict": BOOL,
        "run": STR, "findings": {"type": "array", "items": _FINDING},
        "recorded": {"type": "array", "items": _ATT}}),
]  # fmt: skip
_CLAIM = "A claim convention on an existing attestation, not an object kind."
SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-containment-1": doc("tine-cli-containment-1", "tine containment ... --json",
        "Sandbox policy evidence. `check` fails with `sandbox-policy-mismatch` "
        "(a command-level code) when the recorded policy digest differs from the declared "
        "one; `scan` findings are advisory.", {"anyOf": _SHAPES}),
    "opentine-sandbox-policy-1": doc("opentine-sandbox-policy-1",
        "opentine.sandbox-policy/1 claim", "The sandbox a run was given. " + _CLAIM,
        closed(["convention", "policy", "policy_digest", "recorded_at"], {
            "convention": {"const": "opentine.sandbox-policy/1"}, "policy": POLICY,
            "policy_digest": _DIGEST, "recorded_at": STR})),
    "opentine-containment-finding-1": doc("opentine-containment-finding-1",
        "opentine.containment-finding/1 claim", "One advisory containment finding. " + _CLAIM,
        closed(["convention", "run", "category", "step", "detail", "evidence_digest",
                "found_at"], {
            "convention": {"const": "opentine.containment-finding/1"}, "run": STR,
            "category": _CATEGORY, "step": INT, "detail": STR, "evidence_digest": _DIGEST,
            "found_at": STR})),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"containment {verb}": "tine-cli-containment-1" for verb in ("record", "check", "scan")
}

__all__ = ["COMMAND_SCHEMAS", "POLICY", "SCHEMAS"]
