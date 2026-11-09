"""JSON Schemas for the 0.46 hosted-beta caps and their CLI verbs.

``tine-share-1`` is a share link as ``tine serve`` lists it (never the token);
``tine-list-page-1`` a cursor page of ``GET list/runs|list/refs|log/entries``.
``tine-cli-share-1`` and ``tine-cli-open-1`` are the ``--json`` outputs of
``tine share create|revoke|list`` and ``tine open``.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import INT, STR, closed, doc, open_, opt

_OID: dict[str, Any] = {"type": "string", "pattern": "^[a-z]+:sha256:[0-9a-f]{64}$"}
_SHARE = {"$ref": "tine-share-1.schema.json"}

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-share-1": doc("tine-share-1", "tine serve share link",
        "One share link (`caps.share`): read-only access to one run until `expires` (Unix "
        "seconds) unless revoked. Listings never carry the token; only the 201 answer to "
        "`POST shares` adds `token`, once.",
        open_(["id", "run", "scope", "created_by", "created", "expires", "state"], {
            "id": {"type": "string", "pattern": "^[0-9a-f]{16}$"}, "run": _OID,
            "scope": {"enum": ["read"]}, "created_by": STR, "created": INT, "expires": INT,
            "state": {"enum": ["active", "expired", "revoked"]},
            "token": {"type": "string", "pattern": "^tine_share_[A-Za-z0-9_-]{43}$"}})),
    "tine-list-page-1": doc("tine-list-page-1", "tine serve list page",
        "One page of `GET list/runs`, `GET list/refs` or `GET log/entries`: `items` in key "
        "order and an opaque `next_cursor` (null on the last page).",
        open_(["items", "next_cursor"], {"items": {"type": "array"}, "next_cursor": opt(STR),
                                         "size": INT})),
    "tine-cli-share-1": doc("tine-cli-share-1", "tine share --json",
        "`tine share create|revoke|list --json`: the link created (with its URL, shown "
        "once), the link revoked, or every link in the tenant.",
        open_(["command", "schema", "action"], {
            "command": {"const": "share"}, "schema": {"const": "tine-cli-share/1"},
            "action": {"enum": ["create", "revoke", "list"]},
            "share": _SHARE, "shares": {"type": "array", "items": _SHARE}, "url": STR},
            anyOf=[{"required": ["share"]}, {"required": ["shares"]}])),
    "tine-cli-open-1": doc("tine-cli-open-1", "tine open --json",
        "The web page `tine open` would open for a run.",
        closed(["command", "run", "tenant", "url"], {
            "command": {"const": "open"}, "run": _OID, "tenant": STR, "url": STR})),
}  # fmt: skip

#: ``share`` output carries ``schema: tine-cli-share/1`` (it needs a live remote to drive).
COMMAND_SCHEMAS: dict[str, str] = {"open": "tine-cli-open-1"}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
