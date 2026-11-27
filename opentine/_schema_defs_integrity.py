"""JSON Schema for ``tine integrity check|pin|sign|scan --json`` (0.59; scan 0.60).

A CLI output, not an object kind: the protected-list pin and the taint are
existing attestations under claim conventions (docs/INTEGRITY.md).
"""

from __future__ import annotations

from typing import Any

from opentine._integrity_advisory import ADVISORY_CODES
from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt
from opentine._schema_defs_canary import SCAN

_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_HEAD = {"schema": {"const": "tine-cli-integrity/1"}}
_CODES = ("fail:protected-surface-modified", "fail:protected-list-missing",
          "fail:protected-list-unsigned", "advisory:test-deleted",
          "advisory:holdout-read", "advisory:protected-read", *ADVISORY_CODES,
          "fail:region-outside-modified", "fail:region-file-added", "fail:region-file-removed",
          "fail:region-marker-invalid", "fail:regions-pin-missing",
          "fail:regions-pin-unsigned")  # fmt: skip
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
    "taint": opt(closed(["path", "signer", "hold"], {"path": STR, "signer": STR,
                                                     "hold": opt(STR)}))})  # fmt: skip
_PIN = closed(["command", "schema", "ok", "pins", "list", "signed"], {
    **_HEAD, "command": {"const": "integrity pin"}, "ok": {"const": True}, "pins": INT,
    "list": STR, "signed": {"const": False}})  # fmt: skip
_SIGN = closed(["command", "schema", "ok", "protected_sha256", "signer", "pin"], {
    **_HEAD, "command": {"const": "integrity sign"}, "ok": {"const": True},
    "protected_sha256": _HEX, "signer": STR, "pin": STR})  # fmt: skip
_FINDINGS = {"type": "array", "items": _FINDING}
_RCHECK = closed(["command", "schema", "ok", "baseline_sha256", "files", "findings", "blocking"], {
    **_HEAD, "command": {"const": "integrity region-check"}, "ok": BOOL,
    "baseline_sha256": opt(_HEX), "files": INT, "findings": _FINDINGS,
    "blocking": INT})  # fmt: skip
_RPIN = closed(["command", "schema", "ok", "baseline_sha256", "files", "regions", "signer",
                "pin"], {
    **_HEAD, "command": {"const": "integrity region-pin"}, "ok": {"const": True},
    "baseline_sha256": _HEX, "files": INT, "regions": INT, "signer": STR,
    "pin": STR})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-integrity-1": doc("tine-cli-integrity-1", "tine integrity VERB --json",
        "Protected surfaces of a self-improving agent loop. `check` judges one run's tool "
        "calls (`touched`) and every pinned digest against the signed `.tine/protected.toml`; "
        "`findings` carry `fail:` codes (hash, signature and policy facts, which block: `ok` "
        "is false and the exit 1) and `advisory:` codes (reported, blocking only with "
        "`--strict`); `--record` adds the advisory reward-hack detectors over a run "
        "record. `taint` names the signed `opentine.integrity.taint` attestation filed with "
        "`--key`, and `hold` the object id of the same attestation held as "
        "`integrity-taint:RUN` (0.59), which `tine hold release` refuses. `pin` writes "
        "current digests into the list (`signed` false: re-sign it); "
        "`sign` pins the list's bytes with a policy-role key. `scan` (0.60) lists where "
        "registered canaries occur (`ok` false when any does); `counts` shows how many "
        "objects were read and how many answered from the content-addressed index. "
        "`region-pin` (0.87) signs the code outside EVOLVE-BLOCK regions of the files under "
        "`--glob` (an `opentine.integrity.regions/1` claim); `region-check` judges the working "
        "tree against it (`fail:region-*` and `fail:regions-pin-*` findings; `check` adds "
        "them when a pin is filed).",
        {"oneOf": [_CHECK, _PIN, _SIGN, SCAN, _RPIN, _RCHECK]}),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"integrity {name}": "tine-cli-integrity-1"
    for name in ("check", "pin", "sign", "scan", "region-pin", "region-check")
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
