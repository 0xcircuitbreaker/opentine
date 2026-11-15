"""JSON Schema for ``tine serve token mint|list|revoke --json`` (0.52).

``tine-cli-serve-token-1`` is a CLI output, not an object kind: the records of
scoped API tokens a ``tine serve`` root holds (``opentine.remote._token_store``).
A ``mint`` document also carries the secret, which is shown only that once.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, STR, closed, doc, open_, strs

_TOKEN = closed(
    ["id", "kind", "tenant", "access", "refs", "state", "created_at", "expires_at"],
    {
        "id": {"type": "string", "pattern": "^[0-9a-f]{16}$"},
        "kind": {"enum": ["pat", "ci"]},
        "tenant": STR,
        "access": {"enum": ["read", "write"]},
        "refs": strs(),
        "state": {"enum": ["active", "expired", "revoked"]},
        "created_at": STR,
        "expires_at": STR,
        "revoked_at": STR,
        "label": STR,
    },
)

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-serve-token-1": doc("tine-cli-serve-token-1", "tine serve token --json",
        "Scoped API tokens of a `tine serve` root: per tenant, read or write, limited to ref "
        "namespaces (`*` for all), expiring and revocable. `mint` adds `token`, the secret, "
        "shown only once; the root stores only its SHA-256 digest.",
        open_(["command", "schema", "ok", "tokens"], {
            "command": {"enum": ["serve token mint", "serve token list", "serve token revoke"]},
            "schema": {"const": "tine-cli-serve-token/1"}, "ok": BOOL,
            "tokens": {"type": "array", "items": _TOKEN},
            "token": {"type": "string", "pattern": "^tine_(pat|ci)_[0-9a-f]{16}_"}})),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    "serve token mint": "tine-cli-serve-token-1",
    "serve token list": "tine-cli-serve-token-1",
    "serve token revoke": "tine-cli-serve-token-1",
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
