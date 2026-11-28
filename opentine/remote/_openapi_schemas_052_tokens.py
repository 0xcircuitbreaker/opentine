"""OpenAPI component schemas of the 0.52 admin shapes: tokens, CI exchange, limits.

Unsigned HTTP documents served by ``tine serve`` (``_gateway``); none is an
object kind and none changes the bytes of anything signed.
"""

from __future__ import annotations

from typing import Any

from opentine.remote._openapi_schemas import _int, _obj, _str

_strs = {"type": "array", "items": _str}
_access = {"enum": ["read", "write"]}
_limit = {"anyOf": [_int, {"type": "null"}]}
_METRICS = ("storage_bytes", "egress_bytes", "mirror_bytes", "runner_minutes")
_record = _obj(
    {
        "id": {"type": "string", "pattern": "^[0-9a-f]{16}$"},
        "kind": {"enum": ["pat", "ci"]},
        "tenant": _str,
        "access": _access,
        "refs": _strs,
        "state": {"enum": ["active", "expired", "revoked"]},
        "created_at": _str,
        "expires_at": _str,
    },
    {
        "label": _str,
        "revoked_at": _str,
        "role": {"enum": ["ingest", "verdict", "approve"]},
        "agent": _str,
    },
)
_secret = {"type": "string", "pattern": "^tine_(pat|ci)_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$"}

SCHEMAS_052_TOKENS: dict[str, Any] = {
    "Limits": _obj(
        {
            "policy": _str,
            "never_deletes": {"const": True},
            "defaults": _obj({name: _limit for name in _METRICS}),
            "fair_use": _obj({name: _limit for name in _METRICS}),
            "windows": _obj({name: _str for name in _METRICS}),
            "status": _obj({name: {"enum": [429, 507]} for name in _METRICS}),
        }
    ),
    "AuthMethods": _obj(
        {"methods": {"type": "array", "items": _obj({"type": _str})}},
    ),
    "OidcExchange": _obj({"token": _str}, {"tenant": _str}, extra=False),
    "IssuedToken": _obj(
        {
            "token": _secret,
            "token_id": _str,
            "tenant": _str,
            "access": _access,
            "refs": _strs,
            "expires_at": _str,
            "issued_at": _str,
        }
    ),
    "Usage": _obj(
        {
            "tenant": _str,
            "usage": _obj(
                {name: _obj({"limit": _limit, "used": _int, "window": _str}) for name in _METRICS}
            ),
        }
    ),
    "TokenRecord": _record,
    "TokenList": _obj({"tokens": {"type": "array", "items": _record}}),
    "TokenRequest": _obj(
        {"access": _access, "refs": _strs},
        {
            "ttl_seconds": {"type": "integer", "minimum": 1},
            "label": _str,
            "role": {"enum": ["ingest", "verdict", "approve"]},
            "agent": _str,
        },  # 0.90
        extra=False,
    ),
    "MintedToken": {"allOf": [_record, _obj({"token": _secret})]},
}

__all__ = ["SCHEMAS_052_TOKENS"]
