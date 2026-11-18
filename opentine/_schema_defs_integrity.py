"""JSON Schema for ``tine integrity check|pin|sign --json`` (0.60).

A CLI output, not an object kind: the protected-list pin and the taint are
existing attestations under claim conventions (docs/INTEGRITY.md).
"""

from __future__ import annotations

from typing import Any

from opentine._integrity_advisory import ADVISORY_CODES
from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt

_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_HEAD = {"schema": {"const": "tine-cli-integrity/1"}}
_CODES = ("fail:protected-surface-modified", "fail:protected-list-missing",
          "fail:protected-list-unsigned", "advisory:test-deleted",
          "advisory:holdout-read", *ADVISORY_CODES)  # fmt: skip
_FINDING = closed(["level", "code", "surface", "path", "detail"], {
    "level": {"enum": ["fail", "advisory"]}, "code": {"enum": list(dict.fromkeys(_CODES))},
    "surface": STR, "path": STR, "detail": STR})  # fmt: skip
_TOUCHED = closed(["path", "op", "step"], {
    "path": STR, "op": {"enum": ["write", "delete", "read"]}, "step": STR})  # fmt: skip
_CHECK = closed(["command", "schema", "ok", "run", "protected_sha256", "touched", "findings",
                 "blocking", "taint"], {
    **_HEAD, "command": {"const": "integrity check"}, "ok": BOOL, "run": STR,
    "protected_sha256": opt(_HEX), "touched": {"type": "array", "items": _TOUCHED},
    "findings": {"type": "array", "items": _FINDING}, "blocking": INT,
    "taint": opt(closed(["path", "signer"], {"path": STR, "signer": STR}))})  # fmt: skip
_PIN = closed(["command", "schema", "ok", "pins", "list", "signed"], {
    **_HEAD, "command": {"const": "integrity pin"}, "ok": {"const": True}, "pins": INT,
    "list": STR, "signed": {"const": False}})  # fmt: skip
_SIGN = closed(["command", "schema", "ok", "protected_sha256", "signer", "pin"], {
    **_HEAD, "command": {"const": "integrity sign"}, "ok": {"const": True},
    "protected_sha256": _HEX, "signer": STR, "pin": STR})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-integrity-1": doc("tine-cli-integrity-1", "tine integrity check|pin|sign --json",
        "Protected surfaces of a self-improving agent loop. `check` judges one run's tool "
        "calls (`touched`) and every pinned digest against the signed `.tine/protected.toml`; "
        "`findings` carry `fail:` codes (hash, signature and policy facts, which block: `ok` "
        "is false and the exit 1) and `advisory:` codes (reported, blocking only with "
        "`--strict`); `--record` adds the advisory reward-hack detectors over a run "
        "record. `taint` names the signed `opentine.integrity.taint` attestation filed with "
        "`--key`. `pin` writes current digests into the list (`signed` false: re-sign it); "
        "`sign` pins the list's bytes with a policy-role key.",
        {"oneOf": [_CHECK, _PIN, _SIGN]}),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"integrity {name}": "tine-cli-integrity-1" for name in ("check", "pin", "sign")
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
