"""The OTLP/HTTP endpoint behind ``tine serve --otlp``: stdlib, threaded, JSON.

``POST /v1/traces`` and ``POST /v1/logs`` accept OTLP/JSON
(``application/json``, optionally gzip-encoded) and answer the OTLP success body
``{}`` -- or ``{"partialSuccess": ...}`` when spans without a ``traceId`` were
rejected. Both routes also take ``application/x-protobuf``, decoded by the
stdlib readers in :mod:`opentine.trace._otlp_proto` and (0.48, logs)
:mod:`opentine.trace._otlp_logs_proto`, and answered in JSON; any other
protobuf media type is refused with 415 and a hint. Bodies are
bounded before they are read (413) and decompressed under the same bound; a
body that is not JSON is a 400. Grouping and saving live in
:mod:`opentine._otlp_collect`.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from opentine._otlp_collect import OtlpCollector
from opentine.trace._import_guard import shape_checked

PROTOBUF_HINT = (
    "OTLP/HTTP protobuf must be sent as Content-Type application/x-protobuf "
    "(OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf), or send OTLP/JSON"
)
ROUTES = {"/v1/traces": "add_spans", "/v1/logs": "add_logs"}
#: Spans plus log records one request may carry, and attributes on one item.
MAX_ITEMS, MAX_ATTRIBUTES = 100_000, 1_000
LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})


class _Refused(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def inflate(data: bytes, limit: int) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = decoder.decompress(data, limit + 1)
    except zlib.error as exc:
        raise _Refused(400, f"invalid gzip body: {exc}") from exc
    if len(out) > limit or decoder.unconsumed_tail:
        raise _Refused(413, f"decompressed body exceeds {limit} bytes")
    return out


def check_limits(document: Any) -> None:
    """Refuse a document with too many spans or log records, or attributes on one."""
    items, stack = 0, [document]
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
            continue
        if not isinstance(node, dict):
            continue
        for key, value in node.items():
            if not isinstance(value, list):
                stack.append(value)
                continue
            if key in ("spans", "logRecords", "log_records"):
                items += len(value)
                if items > MAX_ITEMS:
                    raise _Refused(413, f"request carries more than {MAX_ITEMS} spans or logs")
            elif key == "attributes" and len(value) > MAX_ATTRIBUTES:
                raise _Refused(413, f"an item carries more than {MAX_ATTRIBUTES} attributes")
            stack.append(value)


def decode_protobuf(data: bytes, route: str) -> Any:
    """A traces or logs export request, decoded and checked against the item caps."""
    from opentine.trace._otlp_logs_proto import decode_logs
    from opentine.trace._otlp_proto import decode_traces

    try:
        document = (decode_logs if route == "add_logs" else decode_traces)(data)
    except ValueError as exc:
        raise _Refused(400, f"body is not valid OTLP protobuf: {exc}") from exc
    check_limits(document)
    return document


def _host_name(header: str) -> str:
    host = header.strip().lower()
    if host.startswith("["):
        return host[1:].partition("]")[0]
    host = host.rpartition(":")[0] if host.count(":") == 1 else host
    return host.removesuffix(".")


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

    def _body(self, route: str = "add_spans") -> Any:
        kind = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        protobuf = kind == "application/x-protobuf"
        if "protobuf" in kind and not protobuf:
            raise _Refused(415, PROTOBUF_HINT)
        if kind != "application/json" and not protobuf:
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
            data = inflate(data, self.max_bytes)
        elif encoding != "identity":
            raise _Refused(415, f"unsupported Content-Encoding {encoding!r}")
        if protobuf:
            return decode_protobuf(data, route)
        try:
            document = json.loads(shape_checked(data).decode("utf-8"))
        except (RecursionError, UnicodeDecodeError, ValueError) as exc:
            raise _Refused(400, f"body is not valid OTLP/JSON: {exc}") from exc
        if not isinstance(document, dict):
            raise _Refused(400, "body is not valid OTLP/JSON: expected an object")
        check_limits(document)
        return document

    def _check_origin(self) -> None:
        """Refuse browser requests and, on a loopback bind, foreign Host names.

        A DNS-rebinding page reaches 127.0.0.1 under its own name; OTLP
        exporters send no Origin and name the address they were given.
        """
        if self.headers.get("Origin") is not None:
            raise _Refused(403, "cross-origin requests are not accepted")
        try:
            if not ipaddress.ip_address(self.server.server_address[0]).is_loopback:
                return
        except ValueError:
            return
        if _host_name(self.headers.get("Host") or "") not in LOOPBACK_NAMES:
            raise _Refused(403, "Host header must name the loopback address")

    def do_POST(self) -> None:  # noqa: N802 - stdlib name
        route = ROUTES.get(self.path.split("?", 1)[0])
        try:
            if route is None:
                raise _Refused(404, "OTLP/HTTP serves POST /v1/traces and /v1/logs")
            self._check_origin()
            rejected = getattr(self.collector, route)(self._body(route))
        except _Refused as exc:
            self._reply(exc.status, {"code": exc.status, "message": str(exc)})
            return
        except (RecursionError, ValueError) as exc:
            self._reply(400, {"code": 400, "message": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001 - a client must get a reply, not a reset
            self._reply(500, {"code": 500, "message": f"{type(exc).__name__}"})
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


__all__ = [
    "PROTOBUF_HINT",
    "check_limits",
    "decode_protobuf",
    "inflate",
    "OtlpHandler",
    "OtlpServer",
    "start",
]
