"""``tine ingest serve``: a loopback HTTP endpoint for batched ingest (0.77).

``POST /v1/ingest`` takes one batch as JSON Lines (``application/x-ndjson`` or
``application/json``) and answers the signed batch's summary as JSON; each
request is one batch and one durability point. ``GET /v1/ingest`` answers the
stream's held head. Bodies are bounded before they are read (413); a body that
is not JSON Lines of objects is a 400. Appends are serialized, so the chain
never forks under concurrent posts. The listener binds loopback only: the
signing key never answers a request from another host.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from opentine._ingest_policy import IngestError

LOOPBACK = frozenset({"127.0.0.1", "localhost"})
ROUTE = "/v1/ingest"
MAX_CLIENTS = 8  # connections served at once; the rest are answered 503
TIMEOUT_S = 30.0  # a client that stops sending is dropped


def _local_host(value: str | None) -> bool:
    """A ``Host`` header naming loopback: a rebound DNS name never reaches the key."""
    if not value:
        return False
    host = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
    return host in LOOPBACK


class IngestHandler(BaseHTTPRequestHandler):
    server: IngestServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return  # quiet: the CLI prints its own lines

    def _answer(self, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def setup(self) -> None:
        self.timeout = self.server.timeout_s
        super().setup()

    def _refused(self) -> bool:
        """Browsers (an ``Origin``) and foreign ``Host`` names are refused: 403."""
        if self.headers.get("Origin") is not None or not _local_host(self.headers.get("Host")):
            self.close_connection = True
            self._answer(403, {"error": "loopback clients only"})
            return True
        return False

    def handle(self) -> None:
        if not self.server.slots.acquire(blocking=False):
            self.close_connection = True
            self.raw_requestline = self.rfile.readline(65537)
            if self.raw_requestline and self.parse_request():
                self._answer(503, {"error": "too many clients"})
            return
        try:
            super().handle()
        except TimeoutError:
            self.close_connection = True
        finally:
            self.server.slots.release()

    def do_GET(self) -> None:  # noqa: N802
        if self._refused():
            return
        if self.path != ROUTE:
            self._answer(404, {"error": "not found"})
            return
        from opentine import _ingest_holds

        head = _ingest_holds.head(self.server.repo, self.server.stream)
        self._answer(200, {"stream": self.server.stream, "head": head})

    def do_POST(self) -> None:  # noqa: N802
        if self._refused():
            return
        if self.path != ROUTE:
            self._answer(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._answer(411, {"error": "Content-Length is required"})
            return
        if length < 0 or length > self.server.max_bytes:
            self.close_connection = True
            self._answer(413, {"error": f"a batch is at most {self.server.max_bytes} bytes"})
            return
        data = self.rfile.read(length)
        try:
            summary = self.server.append(data)
        except IngestError as exc:
            self._answer(400, {"error": str(exc)})
            return
        self._answer(200, summary)


class IngestServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], repo: Any, stream: str, key: Any,
                 clock_ms: Any, max_bytes: int) -> None:  # fmt: skip
        if address[0] not in LOOPBACK:
            raise ValueError("tine ingest serve binds loopback only (127.0.0.1)")
        super().__init__(address, IngestHandler)
        self.repo, self.stream, self.key = repo, stream, key
        self.clock_ms, self.max_bytes = clock_ms, max_bytes
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(MAX_CLIENTS)
        self.timeout_s = TIMEOUT_S

    def append(self, data: bytes) -> dict[str, Any]:
        from opentine._ingest_batch import append

        with self.lock:  # one writer: the chain never forks
            return append(self.repo, self.stream, data, self.key, at_ms=self.clock_ms())

    def stop(self) -> None:
        self.shutdown()
        self.server_close()


def start(repo: Any, stream: str, key: Any, *, host: str = "127.0.0.1", port: int = 0,
          clock_ms: Any = None, max_bytes: int = 64 * 1024 * 1024) -> IngestServer:  # fmt: skip
    """A running endpoint on its own thread; ``server.stop()`` closes it."""
    import time

    clock = clock_ms or (lambda: int(time.time() * 1000))
    server = IngestServer((host, port), repo, stream, key, clock, max_bytes)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


__all__ = ["IngestServer", "LOOPBACK", "ROUTE", "start"]
