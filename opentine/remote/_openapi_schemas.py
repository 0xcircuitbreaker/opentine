"""Component schemas of the ``tine serve`` OpenAPI v1 document (JSON Schema 2020-12).

They use only the subset :mod:`opentine._jsonschema` validates, so the API
conformance suite checks every JSON response against them without a
``jsonschema`` dependency.
"""

from __future__ import annotations

from typing import Any

OID = r"^(blob|event|run|attestation|annotation):sha256:[0-9a-f]{64}$"
_oid = {"type": "string", "pattern": OID}
_oids = {"type": "array", "items": _oid}
_int = {"type": "integer", "minimum": 0}
_str = {"type": "string"}


def _obj(required: dict[str, Any], optional: dict[str, Any] | None = None, *, extra=True):
    schema: dict[str, Any] = {
        "type": "object",
        "required": sorted(required),
        "properties": {**required, **(optional or {})},
    }
    if not extra:
        schema["additionalProperties"] = False
    return schema


def _ref(name: str) -> dict[str, str]:
    return {"$ref": f"#/components/schemas/{name}"}


SCHEMAS: dict[str, Any] = {
    "Error": _obj({"error": _str}, extra=False),
    "Capabilities": _obj(
        {
            "protocol": {"const": "opentine-remote/1"},
            "object_format": _str,
            "pack_format": _str,
            "pack_formats": {"type": "array", "items": _str},
            "roles": {"type": "array", "items": _str},
            "version": _str,
        },
        {
            "authentication": {"type": "array", "items": _str},
            "ref_txn": {"type": "boolean"},
            "resumable_upload": {"type": "boolean"},
            "events_sse": {"type": "object"},
            "webhooks": {"type": "object"},
            "object_read_http": {"type": "object"},
            "run_closure": {"type": "object"},
            "list": {"type": "object"},
            "share": {"type": "object"},
            "admin": {"type": "object"},
            "project": {"type": "object"},
        },
    ),
    "RefList": _obj({"refs": {"type": "object", "additionalProperties": _oid}}, extra=False),
    "RefUpdate": _obj(
        {"new": _oid},
        {"expected_old": {"anyOf": [_oid, {"type": "null"}]}, "force": {"type": "boolean"}},
        extra=False,
    ),
    "RefTxn": _obj(
        {"updates": {"type": "array", "minItems": 1, "items": {"type": "object"}}},
        {"force": {"type": "boolean"}},
        extra=False,
    ),
    "Updated": _obj({"updated": {"type": "boolean"}}, extra=False),
    "Negotiate": _obj(
        {"wants": _oids},
        {"haves": _oids, "depth": {"anyOf": [_int, {"type": "null"}]}},
        extra=False,
    ),
    "Missing": _obj({"missing": _oids}, extra=False),
    "Fetch": _obj(
        {"wants": _oids},
        {
            "haves": _oids,
            "depth": {"anyOf": [_int, {"type": "null"}]},
            "object_types": {"type": "array", "items": _str},
            "pack_formats": {"type": "array", "items": _str},
            "pack_codecs": {"type": "array", "items": _str},
            "tips": {"type": "object"},
        },
    ),
    "UploadDeclaration": _obj(
        {"sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "size": _int}, extra=False
    ),
    "Installed": _obj(
        {},
        {
            "objects": _int,
            "pack_id": _str,
            "offset": _int,
            "upload_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
        },
        extra=False,
    ),
    "Offset": _obj({"offset": _int}, extra=False),
    "SearchQuery": _obj({}, {"type": _str}),
    "SearchResult": _obj({"objects": _oids, "truncated": {"type": "boolean"}}, extra=False),
    "AuditStatus": _obj(
        {"ok": {"type": "boolean"}, "status": _str, "warnings": {"type": "array"}}, extra=False
    ),
    "Checkpoint": _obj({"checkpoint": _str, "size": _int, "vkey": _str}),
    "Consistency": _obj(
        {"checkpoint": _str, "size": _int, "vkey": _str, "old": _int, "new": _int, "proof": {}}
    ),
    "Receipt": {"type": "object"},
    "WebhookRequest": _obj({"url": _str}, {"kinds": {"type": "array", "items": _str}}, extra=False),
    "Webhook": _obj(
        {
            "id": {"type": "string", "pattern": "^wh_[0-9a-f]{16}$"},
            "url": _str,
            "kinds": {"type": "array", "items": _str},
            "created": _str,
        },
    ),  # fmt: skip
    "WebhookList": _obj(
        {"webhooks": {"type": "array", "items": _ref("Webhook")}, "recent": {"type": "array"}},
        extra=False,
    ),
    "Removed": _obj({"removed": _str}, extra=False),
    "RunPage": _obj(
        {"runs": {"type": "array", "items": _obj({"oid": _oid})}},
        {"next_cursor": {"anyOf": [_str, {"type": "null"}]}},
    ),
    "ShareRequest": _obj(
        {"run": _oid}, {"expires_in": {"type": "integer", "minimum": 1}}, extra=False
    ),
    "Share": _obj({"id": _str, "run": _oid, "url": _str}, {"expires_at": _str}),
    "Quota": _obj({"limits": {"type": "object"}, "usage": {"type": "object"}}),
    "ProjectHistory": _obj({"versions": _oids}),
    "ProjectUpdate": _obj(
        {"manifest": _str, "expected_old": {"anyOf": [_oid, {"type": "null"}]}}, extra=False
    ),
}

__all__ = ["OID", "SCHEMAS"]
