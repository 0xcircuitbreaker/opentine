"""The Streamable HTTP transport of ``tine mcp-proxy``: a local relay to one upstream.

Every POST, GET and DELETE the client sends is forwarded to the upstream MCP
endpoint with its headers (``Mcp-Session-Id`` included) and the reply is
streamed back chunk by chunk, SSE included, before the recorder sees a byte.
On a loopback bind the ``Host`` header must name the loopback address and an
``Origin``, when sent, must be a loopback origin: the DNS-rebinding guard of
the 0.35 OTLP receiver. Request bodies are bounded (413).
"""

from __future__ import annotations

import http.client
import ipaddress
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from opentine._mcp_proxy_record import CLIENT, MAX_MESSAGE, SERVER, McpRecorder
from opentine._otlp_http import LOOPBACK_NAMES, _host_name
from opentine._record_proxy import _HOP

MAX_BODY = 4 * MAX_MESSAGE


class _SseFeed:
    """Split an SSE stream into ``data:`` payloads, keeping at most MAX_MESSAGE bytes."""

    def __init__(self, recorder: McpRecorder) -> None:
        self.recorder, self.line, self.data = recorder, bytearray(), bytearray()

    def write(self, chunk: bytes) -> None:
        self.line += chunk
        while (cut := self.line.find(b"\n")) >= 0:
            line = bytes(self.line[:cut]).rstrip(b"\r")
            del self.line[: cut + 1]
            if not line:
                self.close()
            elif line.startswith(b"data:") and len(self.data) < MAX_MESSAGE:
                self.data += line[5:].removeprefix(b" ") + b"\n"
        if len(self.line) > MAX_MESSAGE:
            self.line.clear()

    def close(self) -> None:
        if self.data.strip():
            self.recorder.feed(SERVER, bytes(self.data), len(self.data) >= MAX_MESSAGE)
        self.data.clear()


class _Handler(BaseHTTPRequestHandler):
    server: McpHttpProxy
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib name
        return

    def _refuse(self, status: int, message: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(message)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(message.encode())
        self.close_connection = True

    def _guard(self) -> str | None:
        if not self.server.loopback:
            return None
        if _host_name(self.headers.get("Host") or "") not in LOOPBACK_NAMES:
            return "Host header must name the loopback address"
        origin = self.headers.get("Origin")
        if origin is not None and (urlsplit(origin).hostname or "") not in LOOPBACK_NAMES:
            return "cross-origin requests are not accepted"
        return None

    def _proxy(self) -> None:
        self._sent = False
        refused = self._guard()
        if refused:
            return self._refuse(403, refused)
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            return self._refuse(413 if length > 0 else 400, "bad or oversized request body")
        body = self.rfile.read(length) if length else b""
        if body:
            self.server.recorder.feed(CLIENT, body[:MAX_MESSAGE], len(body) > MAX_MESSAGE)
        try:
            self._forward(body)
        except (OSError, http.client.HTTPException) as exc:
            if not self._sent:
                self._refuse(502, f"upstream unreachable: {type(exc).__name__}")
            self.close_connection = True

    def _forward(self, body: bytes) -> None:
        target = self.server.upstream
        path = target.path or "/"
        query = urlsplit(self.path).query
        path += "?" + query if query else ""
        kind = (
            http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
        )
        connection = kind(target.netloc, timeout=600)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}
        headers["Accept-Encoding"] = "identity"
        try:
            connection.request(self.command, path, body=body or None, headers=headers)
            response = connection.getresponse()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in _HOP and "\r" not in value and "\n" not in value:
                    self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()
            self._sent, self.close_connection = True, True
            kind_of = (response.getheader("Content-Type") or "").split(";")[0].strip().lower()
            sse = _SseFeed(self.server.recorder) if kind_of == "text/event-stream" else None
            kept = bytearray()
            while chunk := response.read1(65536):
                self.wfile.write(chunk)
                self.wfile.flush()
                if sse is not None:
                    sse.write(chunk)
                elif len(kept) <= MAX_MESSAGE:
                    kept += chunk
            if sse is not None:
                sse.close()
            elif kind_of == "application/json" and kept:
                oversize = len(kept) > MAX_MESSAGE
                self.server.recorder.feed(SERVER, bytes(kept[:MAX_MESSAGE]), oversize)
        finally:
            connection.close()

    do_GET = do_POST = do_DELETE = _proxy


class McpHttpProxy(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], upstream: str, recorder: McpRecorder) -> None:
        super().__init__(address, _Handler)
        self.upstream, self.recorder = urlsplit(upstream), recorder
        try:
            self.loopback = ipaddress.ip_address(self.server_address[0]).is_loopback
        except ValueError:
            self.loopback = False

    @property
    def port(self) -> int:
        return int(self.server_address[1])


def start(address: tuple[str, int], upstream: str, recorder: McpRecorder) -> McpHttpProxy:
    server = McpHttpProxy(address, upstream, recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


__all__ = ["McpHttpProxy", "is_loopback", "start"]
