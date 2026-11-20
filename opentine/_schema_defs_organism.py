"""JSON Schemas for model-organism custody (0.72).

``tine-cli-organism-1`` is the ``tine organism ... --json`` output. The tag,
approval and untag records are claims on attestations (an existing object
kind) and the access-log entry is a held blob, published as
``opentine-organism-tag-1``, ``opentine-organism-approval-1``,
``opentine-organism-untag-1`` and ``opentine-organism-access-1``: conventions,
not object kinds (docs/MODEL_ORGANISMS.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, STR, closed, doc, opt

_HEAD = {"schema": {"const": "tine-cli-organism/1"}}
_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_BLOB = {"type": "string", "pattern": "^blob:sha256:[0-9a-f]{64}$"}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_STATE = {"type": "string", "pattern": "^(verified|unverified: .+)$"}
_STRS = {"type": "array", "items": STR}
_OUTCOME = {"enum": ["allowed", "refused"]}
_TAG = closed(["record", "signer", "verification", "names", "reason", "tagged_at",
               "released_by"], {
    "record": _ATT, "signer": opt(STR), "verification": _STATE, "names": _STRS,
    "reason": STR, "tagged_at": opt(STR), "released_by": opt(_ATT)})  # fmt: skip
_UNTAG = closed(["record", "releases", "verification", "effective"], {
    "record": _ATT, "releases": _STRS, "verification": _STATE, "effective": BOOL})  # fmt: skip
_APPROVAL = closed(["record", "run", "signer", "why", "approved_at", "verification", "valid"], {
    "record": _ATT, "run": opt(STR), "signer": opt(STR), "why": STR, "approved_at": opt(STR),
    "verification": _STATE, "valid": BOOL})  # fmt: skip
_ACCESS = closed(["id", "run", "outcome", "tool", "approval", "at"], {
    "id": _BLOB, "run": opt(STR), "outcome": opt(_OUTCOME), "tool": opt(STR),
    "approval": opt(_ATT), "at": opt(STR)})  # fmt: skip
_ROW = closed(["artifact", "tagged", "live", "names", "tags", "untags", "approvals",
               "accesses"], {
    "artifact": _DIGEST, "tagged": BOOL, "live": {"type": "array", "items": _ATT},
    "names": _STRS, "tags": {"type": "array", "items": _TAG},
    "untags": {"type": "array", "items": _UNTAG},
    "approvals": {"type": "array", "items": _APPROVAL},
    "accesses": {"type": "array", "items": _ACCESS}})  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "artifact", "record"], {
        **_HEAD, "command": {"enum": ["organism tag", "organism untag", "organism approve"]},
        "artifact": _DIGEST, "record": _ATT}),
    closed(["command", "schema", "artifacts"], {
        **_HEAD, "command": {"const": "organism status"},
        "artifacts": {"type": "array", "items": _ROW}}),
]  # fmt: skip
_CLAIM = "A claim convention on an existing attestation, not an object kind."
SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-organism-1": doc("tine-cli-organism-1", "tine organism ... --json",
        "Model-organism tags, load approvals and the access log.", {"anyOf": _SHAPES}),
    "opentine-organism-tag-1": doc("opentine-organism-tag-1", "opentine.organism-tag/1 claim",
        "Marks an artifact (by digest) as a model organism. " + _CLAIM,
        closed(["convention", "artifact", "names", "reason", "tagged_at"], {
            "convention": {"const": "opentine.organism-tag/1"}, "artifact": _DIGEST,
            "names": _STRS, "reason": STR, "tagged_at": STR})),
    "opentine-organism-approval-1": doc("opentine-organism-approval-1",
        "opentine.organism-approval/1 claim",
        "Lets one run load a tagged artifact. " + _CLAIM,
        closed(["convention", "artifact", "run", "why", "approved_at"], {
            "convention": {"const": "opentine.organism-approval/1"}, "artifact": _DIGEST,
            "run": STR, "why": STR, "approved_at": STR})),
    "opentine-organism-untag-1": doc("opentine-organism-untag-1",
        "opentine.organism-untag/1 claim",
        "Releases tag records; effective only with k-of-n oversight approval. " + _CLAIM,
        closed(["convention", "artifact", "releases", "untagged_at"], {
            "convention": {"const": "opentine.organism-untag/1"}, "artifact": _DIGEST,
            "releases": {"type": "array", "items": _ATT}, "untagged_at": STR})),
    "opentine-organism-access-1": doc("opentine-organism-access-1",
        "opentine.organism-access/1 entry",
        "One gated access to a tagged artifact, allowed or refused: a held blob, "
        "not an object kind.",
        closed(["convention", "artifact", "run", "outcome", "tool", "approval", "at"], {
            "convention": {"const": "opentine.organism-access/1"}, "artifact": _DIGEST,
            "run": STR, "outcome": _OUTCOME, "tool": opt(STR), "approval": opt(_ATT),
            "at": STR})),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"organism {verb}": "tine-cli-organism-1" for verb in ("tag", "untag", "approve", "status")
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
