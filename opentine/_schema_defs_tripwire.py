"""JSON Schemas for tripwires and custody quorums (0.91).

``tine-cli-tripwire-1`` is the ``tine tripwire VERB --json`` output and
``tine-cli-custody-quorum-1`` the ``tine custody approve|revoke|approvals
--json`` output. Registry versions, trips, custody approvals and revocations
are attestations (an existing object kind) under the claim conventions
``opentine.tripwire-registry/1``, ``opentine.tripwire-trip/1``,
``opentine.custody-approval/1`` and ``opentine.custody-revocation/1``,
published here as claim shapes, not object kinds.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, NUM, STR, closed, doc, opt

_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_WIRE_KEYS = ["id", "metric", "op", "threshold", "scope", "action", "decoys"]
_WIRE_PROPS = {
    "id": STR, "metric": STR, "op": {"enum": [">=", ">", "<=", "<"]}, "threshold": NUM,
    "scope": STR, "action": {"enum": ["flag", "stop"]},
    "decoys": {"type": "array", "items": _DIGEST}}  # fmt: skip
_WIRE = closed(_WIRE_KEYS, _WIRE_PROPS)
_WIRES = {"type": "array", "items": _WIRE}
_FINDING = closed(["level", "code", "record", "message"], {
    "level": {"const": "fail"},
    "code": {"type": "string", "pattern": "^fail:tripwire\\.[a-z-]+$"},
    "record": opt(_ATT), "message": STR})  # fmt: skip
_FINDINGS = {"type": "array", "items": _FINDING}
_STATUS = {"enum": ["ok", "absent", "unpinned", "broken"]}
REGISTRY = closed(["convention", "serial", "previous", "tripwires", "at"], {
    "convention": {"const": "opentine.tripwire-registry/1"}, "serial": INT,
    "previous": opt(_ATT), "tripwires": _WIRES, "at": STR})  # fmt: skip
TRIP = closed(["convention", "tripwire", "registry", "serial", "value", "evidence", "action",
               "stop", "reason", "at"], {
    "convention": {"const": "opentine.tripwire-trip/1"}, "tripwire": opt(_WIRE),
    "registry": opt(_ATT), "serial": opt(INT), "value": opt(NUM),
    "evidence": {"type": "array", "items": STR}, "action": {"enum": ["flag", "stop"]},
    "stop": opt(_ATT), "reason": STR, "at": STR})  # fmt: skip
_HEAD = {"schema": {"const": "tine-cli-tripwire/1"}}
_ROW = closed([*_WIRE_KEYS, "value", "tripped", "evidence", "error"], {
    **_WIRE_PROPS, "value": opt(NUM), "tripped": BOOL,
    "evidence": {"type": "array", "items": STR}, "error": opt(STR)})  # fmt: skip
_TRIPWIRE = [
    closed(["command", "schema", "record", "serial", "tripwires"], {
        **_HEAD, "command": {"enum": ["tripwire add", "tripwire remove"]}, "record": _ATT,
        "serial": INT, "tripwires": _WIRES}),
    closed(["command", "schema", "status", "head", "serial", "tripwires", "findings",
            "required"], {
        **_HEAD, "command": {"const": "tripwire list"}, "status": _STATUS, "head": opt(_ATT),
        "serial": opt(INT), "tripwires": _WIRES, "findings": _FINDINGS, "required": BOOL}),
    closed(["command", "schema", "registry", "required", "missing", "tripwires", "findings",
            "ok", "recorded"], {
        **_HEAD, "command": {"const": "tripwire check"},
        "registry": closed(["status", "head", "serial"], {
            "status": _STATUS, "head": opt(_ATT), "serial": opt(INT)}),
        "required": BOOL, "missing": BOOL, "tripwires": {"type": "array", "items": _ROW},
        "findings": _FINDINGS, "ok": BOOL,
        "recorded": {"type": "array", "items": closed(["record", "tripwire", "action", "stop"], {
            "record": _ATT, "tripwire": STR, "action": {"enum": ["flag", "stop"]},
            "stop": opt(_ATT)})}}),
    closed(["command", "schema", "trips"], {
        **_HEAD, "command": {"const": "tripwire trips"},
        "trips": {"type": "array", "items": closed(["record", "signer", "counted", "claim"], {
            "record": _ATT, "signer": opt(STR), "counted": BOOL,
            "claim": {"type": ["object", "null"]}})}}),
]  # fmt: skip
APPROVAL = closed(["convention", "operation", "digest", "checkpoint", "requester", "artifact",
                   "destination", "at"], {
    "convention": {"const": "opentine.custody-approval/1"},
    "operation": {"enum": ["copy", "export"]}, "digest": _DIGEST, "checkpoint": opt(_DIGEST),
    "requester": STR, "artifact": opt(STR), "destination": opt(STR), "at": STR})  # fmt: skip
REVOCATION = closed(
    ["convention", "approval", "at"],
    {"convention": {"const": "opentine.custody-revocation/1"}, "approval": _ATT, "at": STR},
)
_REQUEST = {"operation": {"enum": ["copy", "export"]}, "digest": _DIGEST,
            "checkpoint": opt(_DIGEST), "requester": STR}  # fmt: skip
_QHEAD = {"schema": {"const": "tine-cli-custody-quorum/1"}}
_QUORUM = [
    closed(["command", "schema", "record", *_REQUEST], {
        **_QHEAD, "command": {"const": "custody approve"}, "record": _ATT, **_REQUEST}),
    closed(["command", "schema", "record", "approval"], {
        **_QHEAD, "command": {"const": "custody revoke"}, "record": _ATT, "approval": _ATT}),
    closed(["command", "schema", *_REQUEST, "required", "k", "counted", "approvals", "ok"], {
        **_QHEAD, "command": {"const": "custody approvals"}, **_REQUEST, "required": BOOL,
        "k": INT, "counted": INT, "ok": BOOL,
        "approvals": {"type": "array", "items": closed(["record", "signer", "counted", "why"], {
            "record": _ATT, "signer": opt(STR), "counted": BOOL, "why": opt(STR)})}}),
]  # fmt: skip
SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-tripwire-1": doc("tine-cli-tripwire-1", "tine tripwire VERB --json",
        "The signed tripwire registry (0.91). `add` and `remove` sign the next registry "
        "version (`opentine.tripwire-registry/1`) with a pinned policy key; `list` shows the "
        "version in force and every finding; `check` evaluates each tripwire over monitor, "
        "suspicion, ingest and budget signals and, with `--key`, holds the trips "
        "(`opentine.tripwire-trip/1`) and the stop tokens of `stop` actions; `trips` lists "
        "them. `tripwire.*` codes are command-level.", {"oneOf": _TRIPWIRE}),
    "tine-cli-custody-quorum-1": doc("tine-cli-custody-quorum-1",
        "tine custody approve|revoke|approvals --json",
        "k-of-n custody approvals (0.91): `approve` signs one approval by a pinned custodian "
        "key, `revoke` revokes one, `approvals` counts the distinct custodian keys that "
        "approve one request (exit 1 when short).", {"oneOf": _QUORUM}),
    "opentine-tripwire-registry-1": doc("opentine-tripwire-registry-1",
        "opentine.tripwire-registry/1 claim", "One version of the tripwire registry, the "
        "claim of an attestation. A claim convention, not an object kind.", REGISTRY),
    "opentine-tripwire-trip-1": doc("opentine-tripwire-trip-1", "opentine.tripwire-trip/1 claim",
        "One tripped tripwire (or a missing registry under a pinned rule), the claim of a "
        "held attestation.", TRIP),
    "opentine-custody-approval-1": doc("opentine-custody-approval-1",
        "opentine.custody-approval/1 claim", "A custodian's approval of one export or copy "
        "of exact bytes, the claim of a held attestation.", APPROVAL),
    "opentine-custody-revocation-1": doc("opentine-custody-revocation-1",
        "opentine.custody-revocation/1 claim", "The revocation of one custody approval.",
        REVOCATION),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    **{f"tripwire {v}": "tine-cli-tripwire-1" for v in ("add", "remove", "list", "check",
                                                         "trips")},
    **{f"custody {v}": "tine-cli-custody-quorum-1" for v in ("approve", "revoke", "approvals")},
}  # fmt: skip

__all__ = ["APPROVAL", "COMMAND_SCHEMAS", "REGISTRY", "REVOCATION", "SCHEMAS", "TRIP"]
