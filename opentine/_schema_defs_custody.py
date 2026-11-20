"""JSON Schemas for checkpoint and weight custody (0.71).

``tine-cli-custody-weights-1`` is the ``tine custody record --artifact|chain|check
--json`` output. A custody event is a claim on an attestation (an existing object
kind), published as ``opentine-weight-custody-1``: a claim convention, not an
object kind (docs/CUSTODY.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt

_HEAD = {"schema": {"const": "tine-cli-custody-weights/1"}}
_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_STATE = {"type": "string", "pattern": "^(verified|unverified: .+)$"}
_EVENT = {"enum": ["created", "copied", "loaded", "exported", "destroyed", "approved"]}
CLAIM = closed(["convention", "artifact", "event", "seq", "prev", "location", "digest", "size",
                "run", "data", "lineage", "tags", "recorded_at"], {
    "convention": {"const": "opentine.weight-custody/1"}, "artifact": STR, "event": _EVENT,
    "seq": INT, "prev": opt(_ATT), "location": STR, "digest": opt(_DIGEST), "size": opt(INT),
    "run": opt(STR), "data": {"type": "array", "items": _DIGEST}, "lineage": opt(STR),
    "tags": {"type": "array", "items": {"enum": ["model-organism"]}},
    "recorded_at": STR})  # fmt: skip
_FINDING = closed(["code", "record", "message"], {
    "code": {"enum": ["fail:custody-gap", "fail:custody-chain-broken",
                      "fail:custody-unapproved-load", "advisory:custody.signer-unpinned"]},
    "record": opt(_ATT), "message": STR})  # fmt: skip
_ROW = closed(["record", "seq", "event", "signer", "verification", "location", "digest"], {
    "record": _ATT, "seq": opt(INT), "event": opt(STR), "signer": opt(STR),
    "verification": _STATE, "location": opt(STR), "digest": opt(STR)})  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "artifact", "event", "record", "seq", "prev", "digest", "size"], {
        **_HEAD, "command": {"const": "custody record"}, "artifact": STR, "event": _EVENT,
        "record": _ATT, "seq": INT, "prev": opt(_ATT), "digest": opt(_DIGEST),
        "size": opt(INT)}),
    closed(["command", "schema", "artifact", "events"], {
        **_HEAD, "command": {"const": "custody chain"}, "artifact": STR,
        "events": {"type": "array", "items": closed(
            ["record", "seq", "event", "signer", "verification", "claim", "problems"], {
                "record": _ATT, "seq": INT, "event": opt(STR), "signer": opt(STR),
                "verification": _STATE, "claim": {"type": ["object", "null"]},
                "problems": {"type": "array", "items": STR}})}}),
    closed(["command", "schema", "ok", "strict", "artifact", "tagged", "locations", "events",
            "findings"], {
        **_HEAD, "command": {"const": "custody check"}, "ok": BOOL, "strict": BOOL,
        "artifact": STR, "tagged": BOOL,
        "locations": {"type": "object", "additionalProperties": opt(_DIGEST)},
        "events": {"type": "array", "items": _ROW},
        "findings": {"type": "array", "items": _FINDING}}),
]  # fmt: skip
SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-custody-weights-1": doc("tine-cli-custody-weights-1",
        "tine custody record --artifact|chain|check --json",
        "Checkpoint and weight custody. `check` exits 1 on `custody-gap`, "
        "`custody-chain-broken` or `custody-unapproved-load` (command-level codes); "
        "`custody.signer-unpinned` is advisory.", {"anyOf": _SHAPES}),
    "opentine-weight-custody-1": doc("opentine-weight-custody-1",
        "opentine.weight-custody/1 claim", "One custody event of a weight artifact, referenced "
        "by digest only. A claim convention on an existing attestation, not an object kind.",
        CLAIM),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"custody {verb}": "tine-cli-custody-weights-1" for verb in ("record", "chain", "check")
}

__all__ = ["CLAIM", "COMMAND_SCHEMAS", "SCHEMAS"]
