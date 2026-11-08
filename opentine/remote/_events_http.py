"""``GET events`` (Server-Sent Events) and ``GET|POST webhooks``, ``DELETE webhooks/<id>``.

``events`` needs ``read_ref`` in the tenant, the permission that lists refs:
it streams ``tine-event/1`` objects as ``id:``/``event:``/``data:`` frames, a
``: heartbeat`` comment every :data:`HEARTBEAT` seconds, and closes after
:data:`STREAM_SECONDS` (under the server's request deadline) with a ``retry:``
hint, so a client reconnects with ``Last-Event-ID`` and loses nothing still
buffered. A resume point the server cannot honour gets an ``event: reset``
frame first. Webhook routes need ``webhooks``, an admin-only action.
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import parse_qs, unquote

from opentine.remote._audit_tlog_http import audit_routes

HEARTBEAT = 10.0
STREAM_SECONDS = 25.0
MAX_EVENT_ID = 64


def _frame(seq_event: tuple[int, dict[str, Any]]) -> bytes:
    event = seq_event[1]
    data = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return f"id: {event['id']}\nevent: {event['kind']}\ndata: {data}\n\n".encode()


def events_route(app: Any, identity, tenant: str, environ, start_response):
    service = app.service
    hub = getattr(service, "events", None)
    if hub is None:
        return app._json_response(start_response, "404 Not Found", {"error": "not found"})
    service._authorize(identity, "read_ref", tenant)
    query = parse_qs(str(environ.get("QUERY_STRING", ""))[:256])
    last = app._headers(environ).get("last-event-id") or (query.get("last_event_id") or [""])[-1]
    if len(last) > MAX_EVENT_ID:
        raise ValueError("Last-Event-ID is too long")
    if not hub.streams.acquire(blocking=False):
        body = {"error": "too many event streams"}
        return app._json_response(
            start_response, "503 Service Unavailable", body, [("Retry-After", "5")]
        )
    seq, reset = hub.position(last or None)
    start_response(
        "200 OK",
        [
            ("Content-Type", "text/event-stream; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("X-Accel-Buffering", "no"),
        ],
    )
    return _Released(
        hub.streams,
        _stream(
            hub,
            tenant,
            seq,
            reset,
            getattr(app, "stream_seconds", STREAM_SECONDS),
            getattr(app, "heartbeat_seconds", HEARTBEAT),
        ),
    )


class _Released:
    """The stream, releasing its slot exactly once on ``close()`` even if never iterated."""

    def __init__(self, slot, frames):
        self._slot, self._frames, self._open = slot, frames, True

    def __iter__(self):
        return self._frames

    def close(self) -> None:
        try:
            self._frames.close()
        finally:
            if self._open:
                self._open = False
                self._slot.release()


def _stream(hub, tenant: str, seq: int, reset: bool, seconds: float, heartbeat: float):
    yield b"retry: 2000\n\n"
    end = time.monotonic() + seconds
    beat = time.monotonic() + heartbeat
    while True:
        events, lost, head = hub.after(tenant, seq)
        if reset or lost:
            reset = False
            yield b"event: reset\ndata: {}\n\n"
        for item in events:
            seq = item[0]
            yield _frame(item)
        now = time.monotonic()
        if now >= end:
            return
        if now >= beat:
            beat = now + heartbeat
            yield b": heartbeat\n\n"
        hub.wait(head, min(end, beat) - now)


def webhook_routes(app: Any, identity, tenant: str, resource: str, method: str, environ, sr):
    service = app.service
    hooks = getattr(service, "webhooks", None)
    if hooks is None:
        return app._json_response(sr, "404 Not Found", {"error": "not found"})
    service._authorize(identity, "webhooks", tenant)
    if resource == "webhooks" and method == "GET":
        listed = hooks.list(tenant)
        ids = {hook["id"] for hook in listed}
        log = getattr(hooks.dispatcher, "log", ())
        recent = [row for row in log if row["webhook"] in ids]
        return app._json_response(sr, "200 OK", {"recent": recent, "webhooks": listed})
    if resource == "webhooks" and method == "POST":
        request = app._json(environ, "kinds", "url")
        hook = hooks.add(tenant, request.get("url"), request.get("kinds"))
        service._audit(identity, tenant, "webhooks", "ok", {"added": hook["id"]})
        return app._json_response(sr, "201 Created", hook)
    if resource.startswith("webhooks/") and method == "DELETE":
        hook_id = unquote(resource[9:])
        hooks.remove(tenant, hook_id)
        service._audit(identity, tenant, "webhooks", "ok", {"removed": hook_id})
        return app._json_response(sr, "200 OK", {"removed": hook_id})
    return app._json_response(sr, "404 Not Found", {"error": "not found"})


def extra_routes(app: Any, identity, tenant: str, resource: str, method: str, environ, sr):
    """Routes past the core protocol: audit and transparency, events, webhooks."""
    if method == "GET" and (resource == "audit/verify" or resource.startswith("transparency/")):
        return audit_routes(app, identity, tenant, resource, environ, sr)
    if resource == "events" and method == "GET":
        return events_route(app, identity, tenant, environ, sr)
    if resource == "webhooks" or resource.startswith("webhooks/"):
        return webhook_routes(app, identity, tenant, resource, method, environ, sr)
    return app._json_response(sr, "404 Not Found", {"error": "not found"})


__all__ = ["HEARTBEAT", "STREAM_SECONDS", "events_route", "extra_routes", "webhook_routes"]
