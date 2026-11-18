"""OpenAPI component schemas of the 0.55 code mirror (``caps.project.mirror``).

Unsigned HTTP answers of ``tine serve --mirror``: API shapes, not object kinds
(``tests/freeze_inventory.py`` NOT_KINDS). The stored state inside
``MirrorStatus`` is the body of a frozen ``opentine.mirror-state`` (SPEC 4.17).
"""

from __future__ import annotations

from typing import Any

from opentine.remote._openapi_schemas import _int, _obj, _str

_null_str = {"anyOf": [_str, {"type": "null"}]}
_strs = {"type": "array", "items": _str}
_label = _obj(
    {
        "upstream": _str,
        "slot": {"enum": ["primary", "secondary"]},
        "synced_at": _null_str,
        "status": {"enum": ["synced", "stale", "failed", "paused", "never-synced"]},
        "reasons": _strs,
        "computed_by": {"const": "host"},
        "label": _str,
    },
    extra=False,
)
_commit = _obj(
    {
        "oid": _str,
        "parents": _strs,
        "author": _obj({"name": _str, "email": _str}),
        "authored_at": _str,
        "committed_at": _str,
        "subject": _str,
    }
)
_at = {"ref": _str, "commit": _str, "path": _str, "mirror": _label}
_entry = _obj(
    {
        "name": _str,
        "path": _str,
        "type": {"enum": ["blob", "tree", "commit"]},
        "mode": _str,
        "oid": _str,
        "size": {"anyOf": [_int, {"type": "null"}]},
    }
)

SCHEMAS_055: dict[str, Any] = {
    "MirrorLabel": _label,
    "MirrorLink": _obj(
        {},
        {
            "slot": {"enum": ["primary", "secondary"]},
            "url": _str,
            "salt": _str,
            "private": {"type": "boolean"},
        },
        extra=False,
    ),  # fmt: skip
    "MirrorStatus": _obj(
        {
            "mirror": _label,
            "manifest": _null_str,
            "default_branch": _null_str,
            "refs": _int,
            "state": {"anyOf": [{"type": "object"}, {"type": "null"}]},
        },
        extra=False,
    ),
    "MirrorUnlinked": _obj({"unlinked": {"const": True}}, extra=False),
    "CodeRefs": _obj(
        {
            "refs": {"type": "object", "additionalProperties": _str},
            "default_branch": _str,
            "mirror": _label,
        },
        extra=False,
    ),
    "CodeTree": _obj({**_at, "entries": {"type": "array", "items": _entry}}, extra=False),
    "CodeBlob": _obj(
        {
            **_at,
            "oid": _str,
            "size": _int,
            "encoding": {"anyOf": [{"enum": ["utf-8", "base64"]}, {"type": "null"}]},
            "content": _null_str,
            "truncated": {"type": "boolean"},
        },
        extra=False,
    ),
    "CodeHistory": _obj(
        {
            **_at,
            "commits": {"type": "array", "items": _commit},
            "next_cursor": {"anyOf": [_int, {"type": "null"}]},
        },
        extra=False,
    ),
    "CodeCompare": _obj(
        {
            "base": _str,
            "head": _str,
            "ahead_by": _int,
            "behind_by": _int,
            "commits": {"type": "array", "items": _commit},
            "files": {"type": "array", "items": _obj({"status": _str, "path": _str})},
            "files_truncated": {"type": "boolean"},
            "mirror": _label,
        },
        extra=False,
    ),
    "CodeSearch": _obj(
        {
            "commit": _null_str,
            "hits": {
                "type": "array",
                "items": _obj({"path": _str, "line": _int, "snippet": _str}, extra=False),
            },
            "mirror": _label,
        },
        extra=False,
    ),
}
