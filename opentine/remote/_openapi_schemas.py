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
_blob = {"type": "string", "pattern": r"^blob:sha256:[0-9a-f]{64}$"}
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
            "search": {"type": "object"},
            "log_http": {"type": "object"},
            "tombstones": {"type": "boolean"},
            "vsa": {"type": "object"},
            "project": {"type": "object"},
            "social_export": {"type": "object"},
            "reviews": {"type": "object"},
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
    "SearchQuery": _obj(
        {}, {"type": _str, "text": {"type": "string", "minLength": 1, "maxLength": 256}}
    ),
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
    "Closure": _obj(
        {},
        {
            "haves": _oids,
            "depth": {"anyOf": [_int, {"type": "null"}]},
            "lazy_blobs": {"type": "boolean"},
            "pack_formats": {"type": "array", "items": _str},
            "pack_codecs": {"type": "array", "items": _str},
        },
        extra=False,
    ),
    "ListPage": _obj(
        {"items": {"type": "array"}, "next_cursor": {"anyOf": [_str, {"type": "null"}]}},
        {"size": _int},
    ),
    "AdminStats": _obj(
        {
            "objects": {"type": "object", "additionalProperties": _int},
            "refs": _int,
            "shares_active": _int,
        },
    ),  # fmt: skip
    "ShareRequest": _obj(
        {"run": _oid},
        {"ttl": {"type": "integer", "minimum": 1}, "scope": {"enum": ["read"]}},
        extra=False,
    ),
    "Share": _obj(
        {
            "id": {"type": "string", "pattern": "^[0-9a-f]{16}$"},
            "run": _oid,
            "scope": {"enum": ["read"]},
            "created_by": _str,
            "created": _int,
            "expires": _int,
            "state": {"enum": ["active", "expired", "revoked"]},
        },
        {"token": {"type": "string", "pattern": "^tine_share_[A-Za-z0-9_-]{43}$"}},
    ),  # fmt: skip
    "ShareList": _obj({"shares": {"type": "array", "items": _ref("Share")}}, extra=False),
    "SharedRun": _obj({"run": _oid, "scope": {"enum": ["read"]}, "expires": _int}, extra=False),
    "Tombstone": _obj(
        {"kind": {"const": "opentine.tombstone"}, "oid": _oid, "signature": {"type": "object"}}
    ),
    "TombstoneReply": _obj({"tombstone": _ref("Tombstone")}, extra=False),
    "TombstoneStored": _obj(
        {"stored": {"type": "boolean"}, "purged": {"type": "boolean"}}, extra=False
    ),
    # 0.46.1 (caps.project): opentine.project manifests, stored as their owner signed them.
    "ProjectManifest": _obj(
        {"kind": {"const": "opentine.project"}, "seq": _int, "signature": {"type": "object"}}
    ),
    "Project": _obj(
        {"manifest": _ref("ProjectManifest"), "digest": _blob, "seq": _int}, extra=False
    ),
    "ProjectHistory": _obj(
        {
            "versions": {"type": "array", "items": _ref("ProjectManifest")},
            "next_cursor": {"anyOf": [_int, {"type": "null"}]},
            "total": _int,
        },
        extra=False,
    ),  # fmt: skip
    "ProjectUpdate": _obj(
        {"manifest": _ref("ProjectManifest"), "expected_old": {"anyOf": [_blob, {"type": "null"}]}},
        extra=False,
    ),
    "ProjectUpdated": _obj({"updated": {"type": "boolean"}}, {"digest": _blob}, extra=False),
    "SocialCounts": _obj({"stars": _int, "watches": _int}, extra=False),
    # 0.47 (caps.reviews): opentine.review versions and opentine.review-gate decisions.
    "ReviewVersion": _obj(
        {"kind": {"const": "opentine.review"}, "seq": _int, "signature": {"type": "object"}}
    ),
    "ReviewGate": _obj(
        {
            "kind": {"const": "opentine.review-gate"},
            "review": _blob,
            "signature": {"type": "object"},
        }
    ),  # fmt: skip
    "ReviewList": _obj(
        {
            "reviews": {
                "type": "array",
                "items": _obj({"review_id": _str, "seq": _int, "head": _blob}, extra=False),
            }
        },
        extra=False,
    ),  # fmt: skip
    "Review": _obj(
        {
            "bundle": _obj(
                {
                    "kind": {"const": "opentine.review-bundle"},
                    "bundle_version": {"const": 1},
                    "versions": {"type": "array", "items": _ref("ReviewVersion")},
                    "decisions": {"type": "array", "items": _ref("ReviewGate")},
                },
                extra=False,
            ),
            "head": _blob,
            "seq": _int,
        },
        extra=False,
    ),
    "ReviewUpdate": _obj(
        {"version": _ref("ReviewVersion"), "expected_old": {"anyOf": [_blob, {"type": "null"}]}},
        extra=False,
    ),
    "ReviewUpdated": _obj({"updated": {"type": "boolean"}}, {"digest": _blob}, extra=False),
    "ReviewDecision": _obj({"decision": _ref("ReviewGate")}, extra=False),
    "ReviewDecided": _obj({"stored": {"type": "boolean"}, "digest": _blob}, extra=False),
    # 0.47 (caps.coord): opentine-coord/1 task values, as tine task prints them.
    "Task": _obj(
        {
            "task": {"type": "string", "pattern": r"^[a-z0-9][a-z0-9._-]{0,63}$"},
            "title": _str,
            "status": {"enum": ["open", "claimed", "done"]},
            "holder": {"anyOf": [_str, {"type": "null"}]},
            "fencing": _int,
            "lease_expires_ms": {"anyOf": [_int, {"type": "null"}]},
            "updated_ms": _int,
        },
        extra=False,
    ),  # fmt: skip
    "TaskList": _obj({"tasks": {"type": "array", "items": _ref("Task")}}, extra=False),
    "TaskReply": _obj({"task": _ref("Task")}, extra=False),
    "TaskAdd": _obj({"task": _str}, {"title": _str}, extra=False),
    "TaskLease": _obj(
        {"holder": _str},
        {"fencing": _int, "ttl": {"type": "number", "minimum": 0}},
        extra=False,
    ),
    "LeaseRefusal": _obj(
        {"error": _str, "code": {"enum": ["exists", "held", "done", "stale", "contended"]}},
        extra=False,
    ),
}

__all__ = ["OID", "SCHEMAS"]
