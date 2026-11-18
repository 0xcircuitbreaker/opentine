"""JSON Schema for ``tine dataset seal|unseal|exposure`` (0.60).

CLI outputs, not object kinds: the commitment and access records are existing
attestations under claim conventions
(docs/HOLDOUTS.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt

_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_HEAD = {"schema": {"const": "tine-cli-holdout/1"}, "ok": BOOL}
_BUDGET = closed(["max_unseals", "max_items"], {"max_unseals": INT, "max_items": INT})
_REFUSAL = {
    "type": "object", "required": ["code", "detail"], "additionalProperties": False,
    "properties": {"code": STR, "detail": STR}}  # fmt: skip
_REFUSED = closed(["command", "schema", "ok", "refusals"], {
    **_HEAD, "command": STR, "ok": {"const": False},
    "refusals": {"type": "array", "items": _REFUSAL}})  # fmt: skip
_SEAL = closed(["command", "schema", "ok", "out", "holdout", "root", "items", "generation",
                "previous", "budget"], {
    **_HEAD, "command": {"const": "dataset seal"}, "out": STR, "holdout": STR, "root": _HEX,
    "items": INT, "generation": INT, "previous": opt(_HEX), "budget": _BUDGET})  # fmt: skip
_UNSEAL = closed(["command", "schema", "ok", "holdout", "root", "run", "purpose", "items",
                  "out", "over_budget", "access", "access_sha256", "signer"], {
    **_HEAD, "command": {"const": "dataset unseal"}, "holdout": STR, "root": _HEX, "run": STR,
    "purpose": {"enum": ["eval", "other"]}, "items": INT, "out": STR, "over_budget": BOOL,
    "access": STR, "access_sha256": _HEX, "signer": STR})  # fmt: skip
_RECORD = closed(["sequence", "run", "signer", "purpose", "items", "sha256"], {
    "sequence": {"type": ["integer", "null"]}, "run": opt(STR), "signer": STR,
    "purpose": opt(STR), "items": INT, "sha256": _HEX})  # fmt: skip
_LINK = closed(["generation", "root", "commitment_sha256"], {
    "generation": INT, "root": _HEX, "commitment_sha256": _HEX})  # fmt: skip
_EXPOSURE = closed(["command", "schema", "ok", "holdout", "root", "unseals", "revealed",
                    "budget", "over_budget", "chain_ok", "records", "chain"], {
    **_HEAD, "command": {"const": "dataset exposure"}, "holdout": STR, "root": _HEX,
    "unseals": INT, "revealed": INT, "budget": _BUDGET, "over_budget": BOOL,
    "chain_ok": BOOL, "records": {"type": "array", "items": _RECORD},
    "chain": {"type": "array", "items": _LINK}})  # fmt: skip
SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-holdout-1": doc("tine-cli-holdout-1",
        "tine dataset seal|unseal|exposure --json",
        "Sealed holdouts. `seal` commits to the items with a Merkle root (signed claim "
        "`opentine.holdout.commitment/1`) and stores each item TINEAES-sealed; `previous` "
        "names the generation it rotates. `unseal` writes a signed `opentine.holdout.access/1` "
        "record (who, which run, why) before it releases items. `exposure` counts the valid "
        "access records against the budget and checks the commitment chain. Canaries are "
        "`tine-cli-canary-1`. A refusal is `ok` false with `refusals` (`holdout.*`) and exit 1.",
        {"oneOf": [_SEAL, _UNSEAL, _EXPOSURE, _REFUSED]}),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"dataset {name}": "tine-cli-holdout-1" for name in ("seal", "unseal", "exposure")
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
