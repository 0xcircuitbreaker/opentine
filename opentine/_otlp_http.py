"""The OTLP/HTTP endpoint behind ``tine serve --otlp``: stdlib, threaded, JSON.

``POST /v1/traces`` and ``POST /v1/logs`` accept OTLP/JSON
(``application/json``, optionally gzip-encoded) and answer the OTLP success body
``{}`` -- or ``{"partialSuccess": ...}`` when spans without a ``traceId`` were
rejected. OpenTine has no protobuf decoder, so ``application/x-protobuf`` is
refused with 415 and a hint to switch the exporter to ``http/json``. Bodies are
bounded before they are read (413) and decompressed under the same bound; a
body that is not JSON is a 400. Grouping and saving live in
:mod:`opentine._otlp_collect`.
"""

from __future__ import annotations

import json
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from opentine._otlp_collect import OtlpCollector
from opentine.trace._import_guard import shape_checked

PROTOBUF_HINT = (
    "OTLP/HTTP protobuf is not supported; set OTEL_EXPORTER_OTLP_PROTOCOL=http/json "
    "to send OTLP/JSON"
)
ROUTES = {"/v1/traces": "add_spans", "/v1/logs": "add_logs"}


class _Refused(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _inflate(data: bytes, limit: int) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = decoder.decompress(data, limit + 1)
    except zlib.error as exc:
        raise _Refused(400, f"invalid gzip body: {exc}") from exc
    if len(out) > limit or decoder.unconsumed_tail:
        raise _Refused(413, f"decompressed body exceeds {limit} bytes")
    return out


DRAIN_BYTES = 1 << 20  # oversize bodies up to this are read off before a 413


class OtlpHandler(BaseHTTPRequestHandler):
    server_version = "OpenTineOTLP/1"
    timeout = 30
    collector: OtlpCollector
    max_bytes: int

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib name
        return

    def _reply(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        if status >= 400:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(payload)

    def _body(self) -> Any:
        kind = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if "protobuf" in kind:
            raise _Refused(415, PROTOBUF_HINT)
        if kind != "application/json":
            raise _Refused(415, f"unsupported Content-Type {kind or '(none)'!r}; send JSON")
        try:
            length = int(self.headers.get("Content-Length") or "")
        except ValueError as exc:
            raise _Refused(411, "a Content-Length header is required") from exc
        if length < 0 or length > self.max_bytes:
            self.rfile.read(min(max(length, 0), DRAIN_BYTES))  # no RST before the reply
            raise _Refused(413, f"request body exceeds {self.max_bytes} bytes")
        data = self.rfile.read(length)
        encoding = (self.headers.get("Content-Encoding") or "identity").strip().lower()
        if encoding == "gzip":
            data = _inflate(data, self.max_bytes)
        elif encoding != "identity":
            raise _Refused(415, f"unsupported Content-Encoding {encoding!r}")
        try:
            return json.loads(shape_checked(data).decode("utf-8"))
        except (RecursionError, UnicodeDecodeError, ValueError) as exc:
            raise _Refused(400, f"body is not valid OTLP/JSON: {exc}") from exc

    def do_POST(self) -> None:  # noqa: N802 - stdlib name
        route = ROUTES.get(self.path.split("?", 1)[0])
        try:
            if route is None:
                raise _Refused(404, "OTLP/HTTP serves POST /v1/traces and /v1/logs")
            rejected = getattr(self.collector, route)(self._body())
        except _Refused as exc:
            self._reply(exc.status, {"code": exc.status, "message": str(exc)})
            return
        except (RecursionError, ValueError) as exc:
            self._reply(400, {"code": 400, "message": str(exc)})
            return
        if rejected:
            message = f"{rejected} span(s) had no traceId"
            self._reply(
                200, {"partialSuccess": {"rejectedSpans": rejected, "errorMessage": message}}
            )
        else:
            self._reply(200, {})


class OtlpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], collector: OtlpCollector, max_bytes: int) -> None:
        handler = type("_Handler", (OtlpHandler,), {"collector": collector, "max_bytes": max_bytes})
        super().__init__(address, handler)
        self.collector = collector
        self._stop = threading.Event()
        self._sweeper = threading.Thread(target=self._sweep, daemon=True)
        self._sweeper.start()

    def _sweep(self) -> None:
        interval = max(0.05, min(1.0, self.collector.idle / 2))
        while not self._stop.wait(interval):
            self.collector.flush_idle()

    def stop(self) -> None:
        """Stop serving and save every pending group (the Ctrl-C path too)."""
        self._stop.set()
        self.shutdown()
        self.server_close()
        self.collector.flush_all()


def start(collector: OtlpCollector, host: str = "127.0.0.1", port: int = 4318, **kw: Any):
    """A running receiver on its own thread; ``server.stop()`` flushes and closes."""
    server = OtlpServer((host, port), collector, kw.get("max_bytes", 16 * 1024 * 1024))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def serve_otlp(args: Any, console: Any) -> None:
    """``tine serve --otlp``: receive until Ctrl-C, then save what is pending."""
    from opentine._cli_render import _save_run_receipt

    if min(args.otlp_idle, args.max_body_mb) <= 0:
        raise SystemExit("--otlp-idle and --max-body-mb must be positive")
    collector = OtlpCollector(
        lambda run: _save_run_receipt(run, None), idle=args.otlp_idle, report=console.print
    )
    server = start(collector, args.host, args.otlp_port, max_bytes=args.max_body_mb << 20)
    host, port = server.server_address[:2]
    console.print(f"OpenTine OTLP/HTTP receiver on http://{host}:{port} (/v1/traces, /v1/logs)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


__all__ = ["PROTOBUF_HINT", "OtlpHandler", "OtlpServer", "serve_otlp", "start"]
