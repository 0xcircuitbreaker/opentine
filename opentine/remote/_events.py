"""Per-tenant event buffers behind ``GET events`` (SSE) and webhooks (0.45.1).

The remote service reports three kinds of event, each into the tenant it
happened in: ``ref.updated`` (a ref moved by ``PUT refs/...`` or a ref
transaction), ``run.created`` (an installed pack carried runs) and
``log.checkpoint`` (the transparency log grew). Each is a ``tine-event/1``
object whose ``id`` is ``<epoch>-<seq>``: ``epoch`` is random per process, so a
``Last-Event-ID`` from before a restart, or older than the buffer, is answered
with a ``reset`` (the client re-lists refs) instead of a silent gap.

Bounded: :data:`MAX_BUFFER` events per tenant, :data:`MAX_TENANTS` tenant
buffers (least recently written evicted), :data:`MAX_STREAMS` concurrent SSE
streams. Listeners (the webhook dispatcher) are called outside the lock and
their failures never reach the request that caused the event.
"""

from __future__ import annotations

import secrets
import threading
from collections import OrderedDict, deque
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FORMAT = "tine-event/1"
KINDS = ("ref.updated", "run.created", "log.checkpoint")
MAX_BUFFER = 1024
MAX_TENANTS = 1024
MAX_STREAMS = 4
MAX_RUNS_PER_EVENT = 100

Listener = Callable[[dict[str, Any]], None]


class EventHub:
    def __init__(self, *, buffer: int = MAX_BUFFER, max_streams: int = MAX_STREAMS):
        self.epoch = secrets.token_hex(4)
        self._buffer = buffer
        self._cond = threading.Condition()
        self._seq = 0
        self._tenants: OrderedDict[str, deque[tuple[int, dict[str, Any]]]] = OrderedDict()
        self._dropped: dict[str, int] = {}  # tenant -> newest seq evicted from its buffer
        self._dropped_tenants = 0  # newest seq of any evicted tenant buffer
        self._listeners: list[Listener] = []
        self.streams = threading.BoundedSemaphore(max_streams)
        self._checkpoints: dict[str, int] = {}

    def subscribe(self, listener: Listener) -> None:
        self._listeners.append(listener)

    def publish(self, tenant: str, kind: str, data: dict[str, Any]) -> dict[str, Any]:
        if kind not in KINDS:
            raise ValueError(f"unknown event kind {kind!r}")
        with self._cond:
            self._seq += 1
            event = {
                "data": data,
                "format": FORMAT,
                "id": f"{self.epoch}-{self._seq}",
                "kind": kind,
                "tenant": tenant,
                "time": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
            buffer = self._tenants.pop(tenant, None)
            if buffer is None:
                buffer = deque(maxlen=self._buffer)
                if self._dropped_tenants:  # it may have been evicted: resuming needs a reset
                    self._dropped[tenant] = self._dropped_tenants
            if len(buffer) == buffer.maxlen:
                self._dropped[tenant] = buffer[0][0]
            buffer.append((self._seq, event))
            self._tenants[tenant] = buffer
            while len(self._tenants) > MAX_TENANTS:
                gone, rows = self._tenants.popitem(last=False)
                self._dropped.pop(gone, None)
                self._dropped_tenants = max(self._dropped_tenants, rows[-1][0])
            self._cond.notify_all()
        for listener in tuple(self._listeners):
            try:
                listener(event)
            except Exception:  # noqa: BLE001 - a listener never fails the write
                pass
        return event

    def position(self, last_event_id: str | None) -> tuple[int, bool]:
        """``(seq to read after, reset?)`` for a client's ``Last-Event-ID``."""
        with self._cond:
            if not last_event_id:
                return self._seq, False
            epoch, _, raw = last_event_id.partition("-")
            if epoch != self.epoch or not raw.isdigit() or int(raw) > self._seq:
                return 0, True
            return int(raw), False

    def after(self, tenant: str, seq: int) -> tuple[list[tuple[int, dict]], bool, int]:
        """*tenant*'s buffered events after *seq*, whether some were evicted, the head seq."""
        with self._cond:
            buffer = self._tenants.get(tenant)
            events = [item for item in buffer or () if item[0] > seq]
            lost = self._dropped.get(tenant, 0) if buffer else self._dropped_tenants
            return events, 0 < seq < lost, self._seq

    def wait(self, head: int, timeout: float) -> None:
        """Until an event newer than *head* is published, or *timeout*."""
        with self._cond:
            if self._seq == head:
                self._cond.wait(max(0.0, timeout))

    # -- what the service reports ------------------------------------------------

    def ref_moved(self, tenant: str, name: str, old: str | None, new: str, forced: bool) -> None:
        data = {"forced": forced, "name": name, "new": new, "old": old}
        self.publish(tenant, "ref.updated", data)

    def runs_installed(self, tenant: str, oids: list[str]) -> None:
        runs = sorted(oid for oid in oids if oid.startswith("run:"))
        if runs:
            shown = runs[:MAX_RUNS_PER_EVENT]
            self.publish(tenant, "run.created", {"runs": shown, "total": len(runs)})

    def audited(self, tenant: str, audit: Any) -> None:
        """A ``log.checkpoint`` event when the audit transparency log grew."""
        from opentine.remote._audit_tlog import tlog_root

        root = tlog_root(audit)
        try:
            note = (root / "checkpoint").read_text("utf-8") if root else ""
            origin, size, digest = note.split("\n", 3)[:3]
            seen = int(size)
        except (OSError, ValueError):
            return
        key = Path(str(root)).as_posix()
        with self._cond:
            if self._checkpoints.get(key, -1) >= seen:
                return
            self._checkpoints[key] = seen
        self.publish(tenant, "log.checkpoint", {"origin": origin, "root": digest, "size": seen})


def capabilities(service: Any) -> dict[str, Any]:
    """The ``events_sse`` and ``webhooks`` entries of ``GET /v1/capabilities``."""
    caps: dict[str, Any] = {}
    if getattr(service, "events", None) is not None:
        caps["events_sse"] = {"format": FORMAT, "kinds": list(KINDS), "path": "events"}
    hooks = getattr(service, "webhooks", None)
    if hooks is not None:
        caps["webhooks"] = hooks.capabilities()
    return caps


__all__ = ["FORMAT", "KINDS", "MAX_BUFFER", "MAX_STREAMS", "EventHub", "capabilities"]
