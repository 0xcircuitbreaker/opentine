"""The localhost reverse proxy behind ``tine record``: forward, stream back, capture.

Stdlib only. Each provider gets a path prefix (``/openai/...``); the child's SDK
is pointed there through its own base-URL variable, and the proxy forwards the
rest of the path to the upstream that variable named before (or the provider's
public default). Bytes go back to the child unchanged, SSE included, while a
bounded copy is kept for the recorder. Request and response *headers* are never
captured, so an ``Authorization`` or ``x-api-key`` cannot reach the run.
"""

from __future__ import annotations

import http.client
import json
import os
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

#: name -> (base-URL env vars, public default, provider, wire dialect).
UPSTREAMS: dict[str, tuple[tuple[str, ...], str, str, str]] = {
    "openai": (
        ("OPENAI_BASE_URL", "OPENAI_API_BASE"), "https://api.openai.com/v1", "openai", "openai"
    ),
    "anthropic": (("ANTHROPIC_BASE_URL",), "https://api.anthropic.com", "anthropic", "anthropic"),
    "deepseek": (("DEEPSEEK_BASE_URL",), "https://api.deepseek.com", "deepseek", "openai"),
    "xai": (("XAI_BASE_URL",), "https://api.x.ai/v1", "xai", "openai"),
}  # fmt: skip

_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailers", "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding",
}  # fmt: skip
#: The most of one exchange kept for the recorder; the child still gets every byte.
MAX_CAPTURE = 16 * 1024 * 1024


def upstream_bases(environ: dict[str, str]) -> dict[str, str]:
    """Where each provider's calls really go: the child's own setting, else the default."""
    bases = {}
    for name, (variables, default, _, _) in UPSTREAMS.items():
        found = next((environ[v] for v in variables if environ.get(v)), default)
        bases[name] = found.rstrip("/")
    return bases


def child_env(environ: dict[str, str], port: int) -> dict[str, str]:
    env = dict(environ)
    for name, (variables, _, _, _) in UPSTREAMS.items():
        for variable in variables:
            env[variable] = f"http://127.0.0.1:{port}/{name}"
    return env


class _Handler(BaseHTTPRequestHandler):
    server: RecordingServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib name
        return

    def _proxy(self) -> None:
        name, _, rest = self.path.lstrip("/").partition("/")
        if name not in UPSTREAMS:
            self.send_error(404, "unknown provider prefix")
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        started = time.monotonic()
        record: dict[str, Any] = {"upstream": name, "path": "/" + rest, "request": body}
        record["started"] = started
        try:
            self._forward(self.server.bases[name], rest, body, record)
        except (OSError, http.client.HTTPException) as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
            payload = json.dumps(
                {"error": {"type": "upstream_unreachable", "message": record["error"]}}
            )
            if not record.get("sent"):
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload.encode())
        record["duration"] = time.monotonic() - started
        self.server.capture(record)

    def _forward(self, base: str, rest: str, body: bytes, record: dict[str, Any]) -> None:
        target = urlsplit(base)
        path = target.path.rstrip("/") + "/" + rest
        kind = (
            http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
        )
        connection = kind(target.netloc, timeout=600)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}
        headers["Accept-Encoding"] = "identity"  # so the recorder can read what it relays
        try:
            connection.request(self.command, path, body=body or None, headers=headers)
            response = connection.getresponse()
            record["status"] = response.status
            record["content_type"] = response.getheader("Content-Type", "")
            self.send_response(response.status)
            for key, item in response.getheaders():
                if key.lower() not in _HOP:
                    self.send_header(key, item)
            self.send_header("Connection", "close")
            self.end_headers()
            record["sent"] = True
            captured = bytearray()
            while chunk := response.read1(65536):
                self.wfile.write(chunk)
                self.wfile.flush()
                if len(captured) < MAX_CAPTURE:
                    captured += chunk[: MAX_CAPTURE - len(captured)]
            record["response"] = bytes(captured)
        finally:
            connection.close()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _proxy


class RecordingServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, bases: dict[str, str], on_record: Callable[[dict[str, Any]], None]):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.bases = bases
        self._on_record = on_record
        self._lock = threading.Lock()

    def capture(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._on_record(record)

    @property
    def port(self) -> int:
        return int(self.server_address[1])


def start(on_record: Callable[[dict[str, Any]], None]) -> RecordingServer:
    server = RecordingServer(upstream_bases(dict(os.environ)), on_record)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
