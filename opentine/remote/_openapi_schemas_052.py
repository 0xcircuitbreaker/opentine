"""OpenAPI v1 component schemas of the 0.52 admin surface (``caps.session``, ``caps.tenancy``).

None of these carries signed data. Passkey ceremony bodies follow the
WebAuthn JSON shapes (binary fields base64url); see ``_webauthn``.
"""

from __future__ import annotations

from typing import Any

from opentine.remote._openapi_schemas import _int, _obj, _ref, _str

_b64 = {"type": "string", "pattern": r"^[A-Za-z0-9_-]+$"}
_role = {"enum": ["reader", "writer", "admin"]}
_role_or_null = {"anyOf": [_role, {"type": "null"}]}
_int_or_null = {"anyOf": [_int, {"type": "null"}]}
_days = {"type": "number", "minimum": 0}
_tenant = _obj(
    {"name": _str, "display_name": _str, "archived": {"type": "boolean"},
     "created_at": _int_or_null, "role": _role_or_null},
    extra=False,
)  # fmt: skip
_member = _obj({"subject": _str, "role": _role}, extra=False)
_invite = {"id": _str, "tenant": _str, "role": _role, "invited_by": _str, "expires_at": _int}
_hold = _obj({"oid": _str, "target": _str}, extra=False)
_tables = {
    name: {"type": "object", "additionalProperties": _days} for name in ("refs", "status", "tier")
}
_policy = _obj({"keep_days": _days}, _tables, extra=False)
_text_or_null = {"anyOf": [_str, {"type": "null"}]}
_settings_keys = ("description", "homepage", "default_ref")

SCHEMAS_052: dict[str, Any] = {
    "Session": _obj(
        {
            "subject": _str,
            "method": _str,
            "expires_at": _int_or_null,
            "tenants": {"type": "array", "items": _ref("Tenant")},
        },
        extra=False,
    ),  # fmt: skip
    "SessionEnded": _obj({"ended": {"type": "boolean"}}, extra=False),
    "SessionOpened": _obj(
        {
            "token": {"type": "string", "pattern": "^tine_sess_"},
            "subject": _str,
            "method": _str,
            "expires_at": _int,
        },
        extra=False,
    ),  # fmt: skip
    "DevLogin": _obj({"subject": _str}, extra=False),
    "PasskeyRegistrationStart": _obj({}, {"invitation": _str}, extra=False),
    "PasskeyCreationOptions": _obj(
        {
            "challenge": _b64,
            "rp": {"type": "object"},
            "user": {"type": "object"},
            "pubKeyCredParams": {"type": "array"},
            "attestation": {"const": "none"},
        },
    ),  # fmt: skip
    "PasskeyRegistration": _obj(
        {"challenge": _b64, "clientDataJSON": _b64, "attestationObject": _b64},
        {"transports": {"type": "array", "items": _str}, "invitation": _str},
        extra=False,
    ),
    "PasskeyRegistered": _obj(
        {"credential_id": _b64, "subject": _str, "alg": {"enum": [-7, -8]}},
        {"tenant": _ref("Tenant"), "session": _ref("SessionOpened")},
        extra=False,
    ),
    "PasskeyRequestOptions": _obj({"challenge": _b64, "rpId": _str}),
    "PasskeyAssertion": _obj(
        {
            "challenge": _b64,
            "credential_id": _b64,
            "clientDataJSON": _b64,
            "authenticatorData": _b64,
            "signature": _b64,
        },
        {"userHandle": {"anyOf": [_b64, {"type": "null"}]}},
        extra=False,
    ),  # fmt: skip
    "Tenant": _tenant,
    "TenantList": _obj({"tenants": {"type": "array", "items": _tenant}}, extra=False),
    "TenantCreate": _obj({"name": _str}, {"display_name": _str}, extra=False),
    "TenantRename": _obj({"display_name": _str}, extra=False),
    "MemberList": _obj({"members": {"type": "array", "items": _member}}, extra=False),
    "MemberRole": _obj({"role": _role}, extra=False),
    "Invitation": _obj(_invite, extra=False),
    "InvitationList": _obj(
        {"invitations": {"type": "array", "items": _ref("Invitation")}}, extra=False
    ),
    "InvitationCreate": _obj({}, {"role": _role, "ttl_seconds": _int}, extra=False),
    "InvitationCreated": _obj(
        {**_invite, "token": {"type": "string", "pattern": "^tine_invite_"}}, extra=False
    ),
    "InvitationRevoked": _obj({"revoked": _str}, extra=False),
    "InvitationAccept": _obj({"token": _str}, extra=False),
    "TenantSettings": _obj(
        {
            "settings": _obj({}, {k: _str for k in _settings_keys}, extra=False),
            "limits": {"type": "object", "additionalProperties": _int},
        },
        extra=False,
    ),  # fmt: skip
    "SettingsUpdate": _obj({}, {k: _text_or_null for k in _settings_keys}, extra=False),
    "RetentionPolicy": _policy,
    "Retention": _obj(
        {"policy": {"anyOf": [_policy, {"type": "null"}]}, "server_deletes": {"const": False}},
        extra=False,
    ),
    "HoldList": _obj({"holds": {"type": "array", "items": _hold}}, extra=False),
    "HoldRequest": _obj({"oid": _str}, extra=False),
}

__all__ = ["SCHEMAS_052"]
