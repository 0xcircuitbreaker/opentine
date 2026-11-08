"""JSON Schemas for remote events, signed webhook payloads and ``tine watch --json`` (0.45.1)."""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import doc, open_, opt

STR: dict[str, Any] = {"type": "string"}
INT: dict[str, Any] = {"type": "integer", "minimum": 0}
TIME = {"type": "string", "description": "RFC 3339 UTC timestamp"}
KINDS = ["ref.updated", "run.created", "log.checkpoint", "op.logged"]

EVENT = open_(["format", "id", "kind", "tenant", "time", "data"], {
    "format": {"const": "tine-event/1"}, "id": {"type": "string", "minLength": 1},
    "kind": {"enum": KINDS}, "tenant": opt(STR), "time": TIME, "data": {"type": "object"},
})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-event-1": doc("tine-event-1", "tine-event/1",
        "One remote event (the `data:` of an SSE frame on `GET /v1/tenants/<t>/events`, and "
        "the `event` of a webhook payload) or, from `tine watch` on a local repository, one "
        "op-log entry (`op.logged`, tenant null). `data` by kind: `ref.updated` {name, old, "
        "new, forced}; `run.created` {runs (at most 100 oids), total}; `log.checkpoint` "
        "{origin, size, root}; `op.logged` an opentine-op/1 entry.", EVENT),
    "tine-webhook-1": doc("tine-webhook-1", "tine-webhook/1",
        "A webhook delivery body: canonical JSON signed with the server's Ed25519 webhook key "
        "in the `OpenTine-Signature` header (SPEC 8.13).",
        open_(["format", "delivery", "webhook", "event"], {
            "format": {"const": "tine-webhook/1"}, "delivery": STR, "webhook": STR,
            "event": {"$ref": "tine-event-1.schema.json"}})),
    "tine-watch-1": doc("tine-watch-1", "tine watch --json",
        "One JSON Lines record of `tine watch --json`: an event, or a reset (events were "
        "missed; re-list refs).",
        open_(["command", "schema"], {
            "command": {"const": "watch"}, "schema": {"const": "tine-watch/1"},
            "event": {"$ref": "tine-event-1.schema.json"}, "reset": {"const": True}},
            anyOf=[{"required": ["event"]}, {"required": ["reset"]}])),
}  # fmt: skip

__all__ = ["SCHEMAS"]
