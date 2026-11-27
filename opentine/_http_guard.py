"""Slow-client limits shared by the package's HTTP servers (slowloris).

``ThreadingHTTPServer`` starts one thread per connection and its handlers wait
on a socket forever by default, so idle or dripping clients can hold every
thread and file descriptor. :class:`GuardedHandler` and
:class:`GuardedHTTPServer` bound that the way ``tine ingest serve`` (0.77) did
first:

* a per-``recv`` socket timeout (``timeout_s``);
* a whole-request deadline: reads go in chunks through :class:`DeadlineReader`,
  refused once the request's budget is spent (the clock is ``server.monotonic``,
  injectable so tests never wait on the wall clock);
* a cap of ``max_clients`` connections served at once; the rest are answered
  503 and closed;
* daemon handler threads.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from opentine._http_linger import LingeringCloseMixin

TIMEOUT_S = 30.0  # a client that stops sending, or sends too slowly, is dropped
CHUNK = 64 * 1024


class DeadlineReader:
    """The connection's reads, refused once the request's whole-request deadline passed.

    The socket timeout bounds each ``recv`` only; a client dripping one byte at a
    time would otherwise hold a slot forever. Reads go in chunks and the
    deadline is checked before each one.
    """

    def __init__(self, raw: Any, handler: GuardedHandler) -> None:
        self._raw, self._handler = raw, handler

    def _check(self) -> None:
        if self._handler.server.monotonic() > self._handler.deadline:
            raise TimeoutError("the request took too long")

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            raise ValueError("unbounded read")
        parts: list[bytes] = []
        while size > 0:
            self._check()
            chunk = self._raw.read1(min(size, CHUNK))
            if not chunk:
                break
            parts.append(chunk)
            size -= len(chunk)
        return b"".join(parts)

    def readline(self, limit: int = -1) -> bytes:
        parts: list[bytes] = []
        while limit < 0 or limit > 0:
            self._check()
            ahead = self._raw.peek(1)
            if not ahead:
                break
            take = ahead.find(b"\n") + 1 or len(ahead)
            if limit > 0:
                take = min(take, limit)
                limit -= take
            parts.append(self._raw.read(take))
            if parts[-1].endswith(b"\n"):
                break
        return b"".join(parts)

    def close(self) -> None:
        self._raw.close()


class GuardedHandler(BaseHTTPRequestHandler):
    """A request handler held to its server's timeout, deadline and connection cap."""

    server: GuardedHTTPServer
    deadline = 0.0

    def setup(self) -> None:
        self.timeout = self.server.timeout_s
        super().setup()
        self._restart_deadline()
        self.rfile = DeadlineReader(self.rfile, self)  # type: ignore[assignment]

    def _restart_deadline(self) -> None:
        self.deadline = self.server.monotonic() + self.server.timeout_s

    def handle_one_request(self) -> None:
        self._restart_deadline()  # each request (and each keep-alive wait) gets the whole budget
        super().handle_one_request()

    def busy(self) -> None:
        """Answer a connection over the cap (the request line and headers are parsed)."""
        self.send_error(503, "too many clients")

    def handle(self) -> None:
        if not self.server.slots.acquire(blocking=False):
            self.close_connection = True
            try:
                self.raw_requestline = self.rfile.readline(65537)
                if self.raw_requestline and self.parse_request():
                    self.busy()
            except (TimeoutError, OSError):
                pass
            return
        try:
            super().handle()
        except TimeoutError:
            self.close_connection = True
        finally:
            self.server.slots.release()


class GuardedHTTPServer(ThreadingHTTPServer):
    """``ThreadingHTTPServer`` whose :class:`GuardedHandler` handlers are bounded."""

    daemon_threads = True
    max_clients = 32

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.slots = threading.BoundedSemaphore(self.max_clients)
        self.timeout_s = TIMEOUT_S
        self.monotonic = time.monotonic  # injectable: tests never wait on the wall clock


class LingeringGuardedServer(LingeringCloseMixin, GuardedHTTPServer):
    """:class:`GuardedHTTPServer` with a lingering close."""


__all__ = ["CHUNK", "TIMEOUT_S", "DeadlineReader", "GuardedHTTPServer", "GuardedHandler",
           "LingeringGuardedServer"]  # fmt: skip
