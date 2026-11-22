"""JSON Schemas for remote events, signed webhook payloads and ``tine watch --json`` (0.45.1)."""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import closed, doc, open_, opt

STR: dict[str, Any] = {"type": "string"}
INT: dict[str, Any] = {"type": "integer", "minimum": 0}
TIME = {"type": "string", "description": "RFC 3339 UTC timestamp"}
KINDS = ["ref.updated", "run.created", "log.checkpoint", "op.logged"]

EVENT = open_(["format", "id", "kind", "tenant", "time", "data"], {
    "format": {"const": "tine-event/1"}, "id": {"type": "string", "minLength": 1},
    "kind": {"enum": KINDS}, "tenant": opt(STR), "time": TIME, "data": {"type": "object"},
})  # fmt: skip

_NULL_STR = opt(STR)
TAIL = closed(["format", "type", "ref", "run_id", "index", "event_id", "kind", "status",
               "verified", "time_unix", "detail"], {
    "format": {"const": "tine-tail/1"},
    "type": {"enum": ["event", "rewrite", "reset", "dropped"]},
    "ref": _NULL_STR, "run_id": _NULL_STR, "index": opt(INT), "event_id": _NULL_STR,
    "kind": _NULL_STR, "status": {"enum": [None, "verified", "unverified", "invalid"]},
    "verified": {"type": "boolean"}, "time_unix": opt({"type": "number"}),
    "detail": _NULL_STR,
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
    "tine-tail-1": doc("tine-tail-1", "tine-tail/1",
        "One live-tail row (0.77, docs/LIVE.md): the `data:` of an SSE frame on "
        "`GET /v1/tenants/<t>/tail` and the `row` of `tine log -f --json`. `event` rows name "
        "a durable event and its verification status (`verified` only when its bytes hash to "
        "its id and every linked object is present); `rewrite` says a followed ref no longer "
        "extends the run seen before; `reset` an unreadable resume point; `dropped` a slow "
        "consumer cut off. A message format, not an object kind.", TAIL),
    "tine-cli-log-follow-1": doc("tine-cli-log-follow-1", "tine log -f --json",
        "One JSON Lines record of `tine log -f --json`: a tine-tail/1 row.",
        closed(["command", "schema", "row"], {
            "command": {"const": "log"}, "schema": {"const": "tine-cli-log-follow/1"},
            "row": {"$ref": "tine-tail-1.schema.json"}})),
}  # fmt: skip

__all__ = ["SCHEMAS"]
