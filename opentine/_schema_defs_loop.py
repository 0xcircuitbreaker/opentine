"""JSON Schemas for the loop guards (0.58): ``tine keys lint`` and ``tine loop``.

``tine-cli-keys-lint-1`` and ``tine-cli-loop-1`` are CLI outputs, not object
kinds. The stop record itself is an attestation whose claim follows the
``opentine.loop-stop/1`` convention (docs/SPEC.md); no new kind is published.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, STR, closed, doc, open_, opt
from opentine._schema_defs_stop import COMMAND_SCHEMAS as _STOP_COMMANDS
from opentine._schema_defs_stop import SCHEMAS as _STOP

_ROLE = {"enum": ["optimizer", "scorer", "dataset", "verdict", "approver"]}
_FINDING = closed(["level", "code", "role", "key", "message"], {
    "level": {"enum": ["fail", "advisory"]},
    "code": {"type": "string", "pattern": "^(fail|advisory):[a-z0-9.-]+$"},
    "role": opt(_ROLE), "key": opt(FPR), "message": STR})  # fmt: skip
_KEYS = {"type": "array", "items": FPR}
_LOOP = open_(["loop", "status"], {
    "loop": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"},
    "status": {"enum": ["running", "stopped"]},
    "stop": {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"},
    "signer": FPR, "updated_ms": INT,
    "verification": {"type": "string", "pattern": "^(verified|unverified: .+)$"}})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-keys-lint-1": doc("tine-cli-keys-lint-1", "tine keys lint --json",
        "Key separation for self-improving agent loops: the key-role policy "
        "(`.tine/key-roles.toml`) and its findings. A `fail:` finding (the optimizer key also "
        "holds a scorer, dataset, verdict or approver key; a malformed policy) blocks; an "
        "`advisory:` finding blocks only with `--strict`. `blocking` counts what refused. "
        "`pinning` (0.59) says where the roles came from: `pinned` (an owner-signed trust "
        "bundle whose owner key is pinned outside the repository), `unpinned` (only the "
        "unsigned file: it may refuse, never grant) or `absent`.",
        closed(["command", "schema", "ok", "policy", "strict", "roles", "findings", "blocking",
                "pinning"], {
            "pinning": {"enum": ["pinned", "unpinned", "absent"]},
            "command": {"const": "keys lint"}, "schema": {"const": "tine-cli-keys-lint/1"},
            "ok": BOOL, "policy": opt(STR), "strict": BOOL, "blocking": INT,
            "roles": {"type": "object", "additionalProperties": False, "properties": {
                r: _KEYS for r in ("optimizer", "scorer", "dataset", "verdict", "approver",
                                   "policy", "stopper", "eval", "curator",
                                   "monitor", "auditor", "runner", "reviewer")}},
            "findings": {"type": "array", "items": _FINDING}})),
    "tine-cli-loop-1": doc("tine-cli-loop-1", "tine loop stop|status --json",
        "A loop's state. `stopped` names the signed stop attestation (claim convention "
        "`opentine.loop-stop/1`), its signer and whether its Ed25519 signature verifies; "
        "a stopped loop's generations can no longer take or extend a coord lease.",
        closed(["command", "schema", "loop"], {
            "command": {"enum": ["loop stop", "loop status"]},
            "schema": {"const": "tine-cli-loop/1"}, "loop": _LOOP})),
    **_STOP,  # 0.91: tine stop and its claim conventions
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    "keys lint": "tine-cli-keys-lint-1",
    "loop stop": "tine-cli-loop-1",
    "loop status": "tine-cli-loop-1",
    **_STOP_COMMANDS,
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
