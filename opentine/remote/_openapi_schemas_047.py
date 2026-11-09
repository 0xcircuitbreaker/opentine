"""OpenAPI v1 component schemas added in 0.47: Reviews (``caps.reviews``) and coord tasks.

Split from :mod:`opentine.remote._openapi_schemas` (module size budget);
:mod:`opentine.remote._openapi` merges both into one ``components.schemas``.
"""

from __future__ import annotations

from typing import Any

from opentine.remote._openapi_schemas import _blob, _int, _obj, _ref, _str

SCHEMAS_047: dict[str, Any] = {
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

__all__ = ["SCHEMAS_047"]
