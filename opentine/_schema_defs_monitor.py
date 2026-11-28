"""JSON Schemas for monitor verdicts and stop tokens (0.63).

``tine-cli-monitor-1`` is the ``tine monitor ... --json`` output. The verdict
and the stop token are existing attestations; their claims follow the
conventions ``opentine.monitor-verdict/1`` and ``opentine.monitor-stop/1``,
published here as ``opentine-monitor-verdict-1`` and ``opentine-monitor-stop-1``
(claim shapes, not object kinds). ``opentine-monitor-hook-1`` is the generic
answer of ``tine monitor gate`` (docs/MONITORS.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, NUM, STR, closed, doc, opt
from opentine._schema_defs_monitor_eval import EVAL_COMMANDS, EVAL_DESCRIPTION, EVAL_SHAPES
from opentine._schema_defs_monitor_ledger import LEDGER_COMMANDS, LEDGER_DESCRIPTION, LEDGER_SHAPES
from opentine._schema_defs_monitor_ledger import SCHEMAS as _LEDGER_SCHEMAS
from opentine._schema_defs_monitor_protocol import (
    PROTOCOL_COMMANDS,
    PROTOCOL_DESCRIPTION,
    PROTOCOL_SHAPES,
)
from opentine._schema_defs_monitor_protocol import SCHEMAS as _PROTOCOL_SCHEMAS

_OID = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_STATE = {"type": "string", "pattern": "^(verified|unverified: .+)$"}
_ACTION = {"enum": ["allow", "flag", "resample", "defer", "block"]}
_SCOPE = {"type": "string", "pattern": r"^(\*|agent:.+|session:.+)$"}
_STOP = closed(["scope", "token", "verification"], {
    "scope": _SCOPE, "token": opt(_OID), "verification": _STATE})  # fmt: skip
_VERDICT_ROW = closed(["verdict", "verification", "action", "tool", "session", "enforced",
                       "decided_by"], {
    "verdict": _OID, "verification": _STATE, "action": opt(_ACTION), "tool": opt(STR),
    "session": opt(STR), "enforced": opt(BOOL), "decided_by": opt(STR)})  # fmt: skip
_FINDING = closed(["level", "code", "message", "verdict", "run", "step"], {
    "level": {"enum": ["fail", "advisory"]},
    "code": {"type": "string", "pattern": "^(fail|advisory):monitor\\.[a-z-]+$"},
    "message": STR, "verdict": opt(_OID), "run": opt(STR), "step": opt(STR)})  # fmt: skip
_HEAD = {"schema": {"const": "tine-cli-monitor/1"}}
_LISTS = [
    closed(["command", "schema", "stops"], {
        **_HEAD, "command": {"enum": ["monitor stop", "monitor stops"]},
        "stops": {"type": "array", "items": _STOP}}),
    closed(["command", "schema", "verdicts"], {
        **_HEAD, "command": {"const": "monitor verdicts"},
        "verdicts": {"type": "array", "items": _VERDICT_ROW}}),
    closed(["command", "schema", "ok", "strict", "blocking", "verdicts", "blocked_actions",
            "replaced_actions", "runs", "stops", "findings"], {
        **_HEAD, "command": {"const": "monitor verify"}, "ok": BOOL, "strict": BOOL,
        "blocking": INT, "verdicts": INT, "blocked_actions": INT, "replaced_actions": INT,
        "runs": {"type": "array", "items": STR}, "stops": {"type": "array", "items": _STOP},
        "findings": {"type": "array", "items": _FINDING}}),
]  # fmt: skip
_TRAJECTORY = closed(["role", "digest"], {
    "role": {"enum": ["original", "resample", "trusted"]}, "digest": _DIGEST,
    "score": opt(NUM)})  # fmt: skip
VERDICT_CLAIM = closed(
    ["convention", "monitor", "input_digest", "reasoning", "tool", "session", "score",
     "threshold", "action", "enforced", "mode", "decided_by", "latency_ms", "deadline_ms",
     "fail_closed", "trajectories", "chosen", "stop", "decided_at"], {
        "convention": {"const": "opentine.monitor-verdict/1"},
        "monitor": closed(["id", "kind", "model_digest"], {
            "id": STR, "kind": {"enum": ["rule", "command", "http", "probe"]},
            "model_digest": opt(STR), "probe": _DIGEST, "checkpoint": _DIGEST, "layer": INT,
            "threshold": NUM, "calibration": opt(STR)}),  # 0.83: the probe class
        "input_digest": _DIGEST,
        "reasoning": closed(["state", "digest"], {
            "state": {"enum": ["captured", "redacted", "unavailable"]}, "digest": opt(_DIGEST)}),
        "tool": STR, "session": STR, "score": opt(NUM), "threshold": NUM, "action": _ACTION,
        "enforced": BOOL, "mode": {"enum": ["advisory", "gate"]},
        "decided_by": {"enum": ["monitor", "deadline", "error", "stop-token", "alternate"]},
        "latency_ms": INT, "deadline_ms": INT, "fail_closed": BOOL,
        "trajectories": {"type": "array", "minItems": 1, "items": _TRAJECTORY},
        "chosen": {"enum": ["original", "resample", "trusted", "none"]},
        "stop": opt(_OID), "decided_at": STR,
        "category": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"},
        "severity": {"enum": ["low", "medium", "high", "critical"]}})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-monitor-1": doc("tine-cli-monitor-1", "tine monitor ... --json",
        "Inline monitor verdicts and stop tokens. `stop`/`stops` list signed stop tokens "
        "(claim convention `opentine.monitor-stop/1`, held and never released); `verdicts` "
        "lists held monitor verdicts (`opentine.monitor-verdict/1`) and whether each signer "
        "is a pinned monitor key; `verify` checks offline that every blocked or replaced "
        "action in the given runs has its verdict. `fail:` findings block; `advisory:` "
        "findings block only with `--strict`. " + EVAL_DESCRIPTION + PROTOCOL_DESCRIPTION
        + LEDGER_DESCRIPTION,
        {"anyOf": [*_LISTS, *EVAL_SHAPES, *PROTOCOL_SHAPES, *LEDGER_SHAPES]}),
    "opentine-monitor-verdict-1": doc("opentine-monitor-verdict-1",
        "opentine.monitor-verdict/1 claim",
        "The claim of an attestation recording one inline monitor decision. A claim "
        "convention, not an object kind.", VERDICT_CLAIM),
    "opentine-monitor-stop-1": doc("opentine-monitor-stop-1", "opentine.monitor-stop/1 claim",
        "The claim of a signed stop token: gated actions in `scope` are blocked.",
        closed(["convention", "scope", "reason", "stopped_at"], {
            "convention": {"const": "opentine.monitor-stop/1"}, "scope": _SCOPE,
            "reason": STR, "stopped_at": STR})),
    "opentine-monitor-hook-1": doc("opentine-monitor-hook-1", "tine monitor gate (generic)",
        "The generic answer of `tine monitor gate` to one tool call.",
        closed(["protocol", "decision", "verdict", "input", "reason"], {
            "protocol": {"const": "opentine-monitor/1"},
            "decision": {"enum": ["allow", "block", "replace"]}, "verdict": opt(_OID),
            "input": {}, "reason": STR})),
    **_PROTOCOL_SCHEMAS,
    **_LEDGER_SCHEMAS,
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"monitor {verb}": "tine-cli-monitor-1" for verb in ("stop", "stops", "verdicts", "verify")
} | {
    command: "tine-cli-monitor-1"
    for command in (*EVAL_COMMANDS, *PROTOCOL_COMMANDS, *LEDGER_COMMANDS)
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS", "VERDICT_CLAIM"]
