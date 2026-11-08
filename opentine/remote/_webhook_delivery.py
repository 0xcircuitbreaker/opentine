"""Webhook delivery: a signed POST per (registration, event), retried with backoff (0.45.1).

One daemon thread drains a time-ordered queue. A delivery is answered by any
2xx; 408, 429 and 5xx (and connection errors) are retried after
``base * 2**attempt`` seconds (1, 2, 4, 8 s by default) for :data:`ATTEMPTS`
attempts in all, re-signing the timestamp each time; any other status gives
up at once. The queue holds at most :data:`MAX_QUEUE` deliveries; beyond that
new ones are dropped and counted (``dropped``). Redirects are never followed.
The last :data:`MAX_LOG` outcomes are kept for ``GET webhooks``.
"""

from __future__ import annotations

import heapq
import http.client
import itertools
import socket
import ssl
import threading
import time
import uuid
from collections import deque
from typing import Any
from urllib.parse import urlsplit

from opentine import _webhook_sig
from opentine.remote._webhooks import Webhooks, check_url, resolve

ATTEMPTS = 5
MAX_QUEUE = 1000
MAX_LOG = 100
TIMEOUT = 10.0
RETRY = frozenset({408, 429})


class _Pinned(http.client.HTTPSConnection):
    """HTTPS to *address*, with SNI and certificate checks for *host*."""

    def __init__(self, host: str, port: int, address: str, **kwargs: Any):
        super().__init__(host, port, **kwargs)
        self._address = address

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def post(url: str, body: bytes, headers: dict[str, str], allow_private: bool) -> int:
    scheme, host, port = check_url(url, allow_private)
    address = resolve(host, port, allow_private)
    parts = urlsplit(url)
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if scheme == "https":
        context = ssl.create_default_context()
        conn: http.client.HTTPConnection = _Pinned(
            host, port, address, timeout=TIMEOUT, context=context
        )
    else:
        conn = http.client.HTTPConnection(address, port, timeout=TIMEOUT)
    try:
        conn.request("POST", target, body=body, headers={"Host": parts.netloc, **headers})
        response = conn.getresponse()
        response.read(4096)
        return response.status
    finally:
        conn.close()


class Dispatcher:
    def __init__(self, hooks: Webhooks, *, base_delay: float = 1.0, sender=post):
        self.hooks = hooks
        self.base_delay = base_delay
        self.sender = sender
        self.dropped = 0
        self.log: deque[dict[str, Any]] = deque(maxlen=MAX_LOG)
        self._queue: list[tuple[float, int, dict[str, Any]]] = []
        self._order = itertools.count()
        self._cond = threading.Condition()
        self._thread: threading.Thread | None = None

    def __call__(self, event: dict[str, Any]) -> None:
        """An :class:`EventHub` listener: queue one delivery per matching registration."""
        for hook in self.hooks.list(event["tenant"]):
            if event["kind"] in hook.get("kinds", ()):
                payload = {"delivery": str(uuid.uuid4()), "event": event, "webhook": hook["id"]}
                payload["format"] = _webhook_sig.FORMAT
                self._push(0.0, {"attempt": 0, "payload": payload, "url": hook["url"]})

    def _push(self, delay: float, job: dict[str, Any]) -> None:
        with self._cond:
            if len(self._queue) >= MAX_QUEUE:
                self.dropped += 1
                return
            heapq.heappush(self._queue, (time.monotonic() + delay, next(self._order), job))
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, daemon=True)
                self._thread.start()
            self._cond.notify()

    def _next(self) -> dict[str, Any]:
        with self._cond:
            while True:
                if self._queue:
                    due = self._queue[0][0] - time.monotonic()
                    if due <= 0:
                        return heapq.heappop(self._queue)[2]
                    self._cond.wait(due)
                else:
                    self._cond.wait()

    def _run(self) -> None:
        while True:
            self.deliver(self._next())

    def deliver(self, job: dict[str, Any]) -> None:
        payload = job["payload"]
        body = _webhook_sig.canonical_body(payload)
        headers = {"Content-Type": "application/json", "User-Agent": "opentine-webhook/1"}
        headers[_webhook_sig.HEADER] = _webhook_sig.sign(self.hooks.key, body)
        headers[_webhook_sig.DELIVERY_HEADER] = payload["delivery"]
        try:
            status: int | str = self.sender(job["url"], body, headers, self.hooks.allow_private)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            status = type(exc).__name__
        ok = isinstance(status, int) and 200 <= status < 300
        retry = not ok and (not isinstance(status, int) or status in RETRY or status >= 500)
        attempt = job["attempt"] + 1
        outcome = "delivered" if ok else "retrying" if retry and attempt < ATTEMPTS else "failed"
        self.log.append(
            {
                "attempt": attempt,
                "delivery": payload["delivery"],
                "outcome": outcome,
                "status": status,
                "webhook": payload["webhook"],
            }
        )
        if outcome == "retrying":
            self._push(self.base_delay * 2 ** (attempt - 1), {**job, "attempt": attempt})


def attach(hub: Any, hooks: Webhooks, **options: Any) -> Dispatcher:
    dispatcher = Dispatcher(hooks, **options)
    hooks.dispatcher = dispatcher
    hub.subscribe(dispatcher)
    return dispatcher


__all__ = ["ATTEMPTS", "Dispatcher", "attach", "post"]
