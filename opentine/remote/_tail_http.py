"""``GET tail`` (Server-Sent Events): follow a tenant's run events as they become durable (0.77).

The same engine as ``tine log -f`` (:mod:`opentine._tail`) over the tenant's
stored objects. Authorization and tenant scoping are those of the other tenant
reads: tenant-wide ``read_ref`` (the ref listing) and ``fetch`` (the events
themselves), which a namespace-limited token is never granted (as ``GET
events``), with the per-object read policy applied; a caller who may not read
the tenant gets the uniform 404. Opening a stream is audited.

Query: ``ref`` (default ``heads/main``) or ``all=1`` (every run ref), ``lines``
(events already there to show first, at most :data:`MAX_LINES`) and
``last_event_id`` (or the ``Last-Event-ID`` header) to resume. Each row is a
``tine-tail/1`` object in an ``event: <type>`` frame; the last frame of every
batch carries ``id:``, a cursor naming where the stream is, so delivery after a
reconnect is at least once (rows carry their ``event_id``). A cursor this
server cannot read is answered with ``event: reset`` and the stream starts at
the present.

Bounded: :data:`MAX_STREAMS` streams in all and :data:`MAX_PER_CLIENT` per
caller (tenant and subject); a ``: heartbeat`` comment every ``HEARTBEAT``
seconds; streams close after ``STREAM_SECONDS`` with a ``retry:`` hint. Slow
clients are dropped, not buffered: nothing is queued per stream (rows are read
from storage when the client can take them), and a client that stays more
than :data:`MAX_LAG` rows behind, or takes longer than :data:`SEND_SECONDS` to
take one batch, gets ``event: dropped`` and the stream ends. It resumes from its
last ``id:`` like any reconnect.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any
from urllib.parse import parse_qs

from opentine._tail import MAX_CURSOR, Follower, row
from opentine.remote._events_http import HEARTBEAT, STREAM_SECONDS
from opentine.remote._tenant_repo import TenantRepo
from opentine.remote._token_scope import visible_refs

MAX_STREAMS = 32
MAX_PER_CLIENT = 4
MAX_LINES = 1000
BATCH = 500
MAX_LAG = 20_000
SEND_SECONDS = 10.0
POLL_SECONDS = 0.5
_ATTACH = threading.Lock()


class TailLimits:
    """Global and per-caller counts of open tail streams."""

    def __init__(self, total: int = MAX_STREAMS, per_client: int = MAX_PER_CLIENT):
        self.total, self.per_client = total, per_client
        self._lock = threading.Lock()
        self._open: dict[tuple[str, str], int] = {}

    def acquire(self, key: tuple[str, str]) -> str | None:
        """``None`` when a slot was taken, else why not (``"server"`` or ``"client"``)."""
        with self._lock:
            if sum(self._open.values()) >= self.total:
                return "server"
            if self._open.get(key, 0) >= self.per_client:
                return "client"
            self._open[key] = self._open.get(key, 0) + 1
            return None

    def release(self, key: tuple[str, str]) -> None:
        with self._lock:
            left = self._open.get(key, 0) - 1
            if left > 0:
                self._open[key] = left
            else:
                self._open.pop(key, None)

    def open(self) -> int:
        with self._lock:
            return sum(self._open.values())


def limits(service: Any) -> TailLimits:
    with _ATTACH:
        found = getattr(service, "tail_limits", None)
        if found is None:
            found = service.tail_limits = TailLimits()
        return found


def _frame(item: dict[str, Any], cursor: str | None = None) -> bytes:
    data = json.dumps(item, sort_keys=True, separators=(",", ":"))
    head = f"id: {cursor}\n" if cursor else ""
    return f"{head}event: {item['type']}\ndata: {data}\n\n".encode()


def tail_route(app: Any, identity, tenant: str, environ, start_response):
    service = app.service
    # Tenant-wide reads, as GET events: a namespace-limited token is never granted them.
    service._authorize(identity, "read_ref", tenant)
    service._authorize(identity, "fetch", tenant)
    query = parse_qs(str(environ.get("QUERY_STRING", ""))[: MAX_CURSOR + 512])
    last = app._headers(environ).get("last-event-id") or (query.get("last_event_id") or [""])[-1]
    if len(last) > MAX_CURSOR:
        raise ValueError("Last-Event-ID is too long")
    lines_raw = (query.get("lines") or ["0"])[-1]
    if not lines_raw.isdigit() or int(lines_raw) > MAX_LINES:
        raise ValueError(f"lines must be 0..{MAX_LINES}")
    every = (query.get("all") or [""])[-1] in ("1", "true")
    names = None if every else [(query.get("ref") or ["heads/main"])[-1]]
    key = (tenant, str(identity.subject))
    slots = limits(service)
    refused = slots.acquire(key)
    if refused is not None:
        status = "503 Service Unavailable" if refused == "server" else "429 Too Many Requests"
        body = {"error": "too many tail streams"}
        return app._json_response(start_response, status, body, [("Retry-After", "5")])
    try:
        repo = TenantRepo(tenant, service.objects, service.index)
        policy = getattr(service, "object_policy", None)
        allow = (lambda oid: policy(tenant, oid)) if callable(policy) else None

        def refs() -> dict[str, str]:
            return visible_refs(identity, service.index.list_refs(tenant))

        service._audit(identity, tenant, "fetch", "ok", {"tail": "all" if every else names[0]})
        reset = False
        options = {"names": names, "allow": allow, "backlog": int(lines_raw)}
        try:
            follower = Follower(repo, refs, resume=last or None, **options)
        except ValueError:
            reset = True
            follower = Follower(repo, refs, **options)
    except BaseException:
        slots.release(key)
        raise
    start_response(
        "200 OK",
        [
            ("Content-Type", "text/event-stream; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("X-Accel-Buffering", "no"),
        ],
    )
    frames = _stream(app, follower, reset)
    return _Slot(lambda: slots.release(key), frames)


class _Slot:
    """The stream, giving its slot back exactly once on ``close()`` even if never iterated."""

    def __init__(self, release, frames):
        self._release, self._frames, self._open = release, frames, True

    def __iter__(self):
        return self._frames

    def close(self) -> None:
        try:
            self._frames.close()
        finally:
            if self._open:
                self._open = False
                self._release()


def _stream(app: Any, follower: Follower, reset: bool):
    clock = getattr(app, "tail_clock", None) or time.monotonic
    hub = getattr(app.service, "events", None)
    seconds = getattr(app, "stream_seconds", STREAM_SECONDS)
    heartbeat = getattr(app, "heartbeat_seconds", HEARTBEAT)
    batch = getattr(app, "tail_batch", BATCH)
    max_lag = getattr(app, "tail_max_lag", MAX_LAG)
    send = getattr(app, "tail_send_seconds", SEND_SECONDS)
    yield b"retry: 2000\n\n"
    if reset:
        yield _frame(row("reset", detail="unknown resume point"), follower.cursor())
    end = clock() + seconds
    beat = clock() + heartbeat
    behind = 0
    while True:
        head = hub.position(None)[0] if hub is not None else 0
        rows = follower.poll(batch)
        if rows:
            cursor = follower.cursor()
            started = clock()
            yield b"".join(
                _frame(item, cursor if i == len(rows) - 1 else None) for i, item in enumerate(rows)
            )
            behind = behind + len(rows) if len(rows) >= batch else 0
            slow = clock() - started > send
            if slow or behind > max_lag:
                reason = "slow consumer" if slow else "consumer lagging"
                yield _frame(row("dropped", detail=reason))
                return
        now = clock()
        if now >= end:
            return
        if now >= beat:
            beat = now + heartbeat
            yield b": heartbeat\n\n"
        if rows and len(rows) >= batch:
            continue  # more is waiting: send it before sleeping
        timeout = max(0.0, min(end, beat, now + POLL_SECONDS) - now)
        if hub is not None:
            hub.wait(head, timeout)
        else:
            threading.Event().wait(timeout)


__all__ = ["MAX_PER_CLIENT", "MAX_STREAMS", "TailLimits", "tail_route"]
