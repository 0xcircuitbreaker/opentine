"""JSON Schemas for the loop guards (0.58): ``tine keys lint`` and ``tine loop``.

``tine-cli-keys-lint-1`` and ``tine-cli-loop-1`` are CLI outputs, not object
kinds. The stop record itself is an attestation whose claim follows the
``opentine.loop-stop/1`` convention (docs/SPEC.md); no new kind is published.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, STR, closed, doc, opt

_ROLE = {"enum": ["optimizer", "scorer", "dataset", "verdict", "approver"]}
_FINDING = closed(["level", "code", "role", "key", "message"], {
    "level": {"enum": ["fail", "advisory"]},
    "code": {"type": "string", "pattern": "^(fail|advisory):[a-z0-9.-]+$"},
    "role": opt(_ROLE), "key": opt(FPR), "message": STR})  # fmt: skip
_KEYS = {"type": "array", "items": FPR}

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-keys-lint-1": doc("tine-cli-keys-lint-1", "tine keys lint --json",
        "Key separation for self-improving agent loops: the key-role policy "
        "(`.tine/key-roles.toml`) and its findings. A `fail:` finding (the optimizer key also "
        "holds a scorer, dataset, verdict or approver key; a malformed policy) blocks; an "
        "`advisory:` finding blocks only with `--strict`. `blocking` counts what refused.",
        closed(["command", "schema", "ok", "policy", "strict", "roles", "findings", "blocking"], {
            "command": {"const": "keys lint"}, "schema": {"const": "tine-cli-keys-lint/1"},
            "ok": BOOL, "policy": opt(STR), "strict": BOOL, "blocking": INT,
            "roles": {"type": "object", "additionalProperties": False, "properties": {
                r: _KEYS for r in ("optimizer", "scorer", "dataset", "verdict", "approver")}},
            "findings": {"type": "array", "items": _FINDING}})),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    "keys lint": "tine-cli-keys-lint-1",
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
