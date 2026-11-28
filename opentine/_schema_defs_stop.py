"""JSON Schemas for ``tine stop init|issue|continue|status|compliance --json`` (0.91).

``tine-cli-stop-1`` is a CLI output. Fleet stops, continue proofs and
stop-compliance records are existing attestations under the claim conventions
``opentine.fleet-stop/1``, ``opentine.stop-continue/1`` and
``opentine.stop-compliance/1``; the stop policy is a file convention
(``opentine.stop-policy/1``). All four are published here as shapes; none is an
object kind.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, STR, closed, doc, opt

_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_BLOB = {"type": "string", "pattern": "^blob:sha256:[0-9a-f]{64}$"}
_FLEET = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"}
_CODE = {"type": "string", "pattern": "^stop\\.[a-z-]+$"}
_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_POINT = closed(["origin", "size", "root"], {"origin": STR, "size": INT, "root": _HEX})
_POLICY_KEYS = ["convention", "fleet", "channel", "vkey", "window_s", "skew_s", "watchdog_s"]
_POLICY = closed(_POLICY_KEYS, {
    "convention": {"const": "opentine.stop-policy/1"}, "fleet": _FLEET, "channel": STR,
    "vkey": STR, "window_s": INT, "skew_s": INT, "watchdog_s": INT})  # fmt: skip
_STOP_KEYS = ["convention", "fleet", "reason", "stopped_at", "channel", "checkpoint"]
_STOP = closed(_STOP_KEYS, {
    "convention": {"const": "opentine.fleet-stop/1"}, "fleet": _FLEET, "reason": STR,
    "stopped_at": STR, "channel": STR, "checkpoint": _POINT})  # fmt: skip
_CONT_KEYS = ["convention", "fleet", "run", "seq", "issued_at", "window_s", "channel",
              "checkpoint"]  # fmt: skip
_CONT = closed(_CONT_KEYS, {
    "convention": {"const": "opentine.stop-continue/1"}, "fleet": _FLEET, "run": STR,
    "seq": INT, "issued_at": STR, "window_s": INT, "channel": STR,
    "checkpoint": _POINT})  # fmt: skip
_COMP_KEYS = ["convention", "fleet", "run", "code", "stop", "stop_issued_at", "requested_at",
              "halted_at", "time_to_halt_ms", "since_stop_ms", "window_s", "watchdog_s",
              "skew_s", "residual_processes", "residual_method", "forwarded_after_stop",
              "refused_after_stop", "compliant"]  # fmt: skip
_COMP = closed(_COMP_KEYS, {
    "convention": {"const": "opentine.stop-compliance/1"}, "fleet": _FLEET, "run": STR,
    "code": _CODE, "stop": opt(STR), "stop_issued_at": opt(STR), "requested_at": STR,
    "halted_at": STR, "time_to_halt_ms": INT, "since_stop_ms": opt(INT), "window_s": INT,
    "watchdog_s": INT, "skew_s": INT, "residual_processes": INT,
    "residual_method": {"enum": ["proc", "killpg", "job-object", "in-process"]},
    "forwarded_after_stop": INT, "refused_after_stop": INT, "compliant": BOOL})  # fmt: skip
_ENTRY = closed(["kind", "attestation", "index", "signer", "claim"], {
    "kind": {"enum": ["stop", "continue"]}, "attestation": _ATT, "index": INT, "signer": FPR,
    "claim": {"anyOf": [_STOP, _CONT]}})  # fmt: skip
_PROOF = closed(["proof", "seq", "issued_at", "age_ms", "window_s", "checkpoint"], {
    "proof": _ATT, "seq": INT, "issued_at": STR, "age_ms": INT, "window_s": INT,
    "checkpoint": _POINT})  # fmt: skip
_ROW = closed(["record", "run", "code", "time_to_halt_ms", "residual_processes", "compliant",
               "problem"], {
    "record": _ATT, "run": opt(STR), "code": opt(STR), "time_to_halt_ms": opt(INT),
    "residual_processes": opt(INT), "compliant": BOOL, "problem": opt(STR)})  # fmt: skip
_HEAD = {"schema": {"const": "tine-cli-stop/1"}}
_SHAPES = [
    closed(["command", "schema", "policy", "held"], {
        **_HEAD, "command": {"const": "stop init"}, "policy": _POLICY, "held": _BLOB}),
    closed(["command", "schema", "entries"], {
        **_HEAD, "command": {"enum": ["stop issue", "stop continue"]},
        "entries": {"type": "array", "items": _ENTRY}}),
    closed(["command", "schema", "fleet", "channel", "window_s", "run", "ok", "code", "message",
            "proof", "stops", "runs", "checkpoint"], {
        **_HEAD, "command": {"const": "stop status"}, "fleet": opt(_FLEET), "channel": opt(STR),
        "window_s": opt(INT), "run": opt(STR), "ok": BOOL, "code": opt(_CODE),
        "message": opt(STR), "proof": opt(_PROOF), "stops": {"type": "array", "items": _ATT},
        "runs": {"type": "array", "items": STR}, "checkpoint": opt(_POINT)}),
    closed(["command", "schema", "records", "ok"], {
        **_HEAD, "command": {"const": "stop compliance"},
        "records": {"type": "array", "items": _ROW}, "ok": BOOL}),
]  # fmt: skip
SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-stop-1": doc("tine-cli-stop-1", "tine stop init|issue|continue|status|compliance "
        "--json",
        "The fleet-wide fail-closed stop. `init` installs the stop policy; `issue` and "
        "`continue` publish signed fleet stops and continue proofs to the stop channel; "
        "`status` says whether a run may act now (`code` names why not); `compliance` lists "
        "the signed records of how halted runs stopped.",
        {"anyOf": _SHAPES}),
    "opentine-stop-policy-1": doc("opentine-stop-policy-1", "opentine.stop-policy/1 file",
        "A repository's stop policy (`.tine/stop-policy.json`): its fleet, stop channel, "
        "the channel's verifier key and the freshness window. A file convention.",
        _POLICY),
    "opentine-fleet-stop-1": doc("opentine-fleet-stop-1", "opentine.fleet-stop/1 claim",
        "The claim of an attestation stopping a fleet, bound to a stop-channel checkpoint.",
        _STOP),
    "opentine-stop-continue-1": doc("opentine-stop-continue-1",
        "opentine.stop-continue/1 claim",
        "The claim of an attestation letting one run of a fleet keep acting for at most "
        "`window_s` seconds, bound to a stop-channel checkpoint and a per-run sequence.",
        _CONT),
    "opentine-stop-compliance-1": doc("opentine-stop-compliance-1",
        "opentine.stop-compliance/1 claim",
        "The claim of an attestation, signed by the runner, recording how a halted run "
        "stopped: time to halt, residual processes and actions after the stop.",
        _COMP),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {f"stop {v}": "tine-cli-stop-1"
                                   for v in ("init", "issue", "continue", "status",
                                             "compliance")}  # fmt: skip

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
