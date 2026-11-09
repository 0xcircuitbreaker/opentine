"""OTLP/gRPC ingest for ``tine serve --otlp --otlp-protocol grpc|both`` (0.48).

Needs the ``opentine[grpc]`` extra (``grpcio``); no generated stubs: the two
unary ``Export`` methods (``TraceService`` and ``LogsService`` of
``opentelemetry.proto.collector.*.v1``) take raw bytes, decoded by the same
bounded stdlib readers as OTLP/HTTP protobuf and grouped by the same
:class:`~opentine._otlp_collect.OtlpCollector`. The controls are those of
``docs/security/otlp-grpc-review.md``:

* ``grpc.max_receive_message_length`` bounds every message, compressed or not
  (grpc core applies it to the decompressed message, so a gzip bomb is a
  ``RESOURCE_EXHAUSTED``, never an allocation); the decoder's field, depth and
  item caps then apply as on HTTP.
* a bounded worker pool, ``maximum_concurrent_rpcs``, per-connection stream and
  metadata limits, and keepalive enforcement.
* a bearer token (``--otlp-token-file``) checked in constant time on every
  call; TLS from ``--cert``/``--key``. Off loopback both are required.
"""

from __future__ import annotations

import hmac
import threading
from concurrent import futures
from pathlib import Path
from typing import Any

from opentine._otlp_collect import OtlpCollector
from opentine._otlp_http import _Refused, decode_protobuf

SERVICES = {
    "opentelemetry.proto.collector.trace.v1.TraceService": "add_spans",
    "opentelemetry.proto.collector.logs.v1.LogsService": "add_logs",
}
WORKERS, MAX_RPCS, MAX_METADATA = 8, 16, 16 * 1024
EXTRA_HINT = "OTLP/gRPC needs the grpc extra: pip install 'opentine[grpc]'"


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def response(rejected: int, message: str = "") -> bytes:
    """An ``Export*ServiceResponse``: empty, or ``partial_success`` {rejected, message}."""
    if not rejected:
        return b""
    text = message.encode("utf-8")
    inner = b"\x08" + _varint(rejected) + b"\x12" + _varint(len(text)) + text
    return b"\x0a" + _varint(len(inner)) + inner


def _authorized(context: Any, token: bytes | None) -> bool:
    if token is None:
        return True
    found = False
    for key, value in context.invocation_metadata() or ():
        if key.lower() == "authorization":
            given = value.encode("utf-8") if isinstance(value, str) else bytes(value)
            found = hmac.compare_digest(given, b"Bearer " + token)
            if not found:  # every authorization value must match, not just the first
                return False
    return found


def _method(grpc: Any, collector: OtlpCollector, route: str, token: bytes | None) -> Any:
    def export(request: bytes, context: Any) -> bytes:
        if not _authorized(context, token):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "a valid bearer token is required")
        try:
            rejected = getattr(collector, route)(decode_protobuf(request, route))
        except _Refused as exc:
            code = grpc.StatusCode.RESOURCE_EXHAUSTED if exc.status == 413 else None
            context.abort(code or grpc.StatusCode.INVALID_ARGUMENT, str(exc))
        except (RecursionError, ValueError) as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
        what = "span(s) had no traceId" if route == "add_spans" else "log record(s) refused"
        return response(rejected, f"{rejected} {what}" if rejected else "")

    return grpc.unary_unary_rpc_method_handler(export)


def options(max_bytes: int) -> list[tuple[str, int]]:
    return [
        ("grpc.max_receive_message_length", max_bytes),
        ("grpc.max_send_message_length", 64 * 1024),
        ("grpc.max_concurrent_streams", 16),
        ("grpc.max_metadata_size", MAX_METADATA),
        ("grpc.http2.max_pings_without_data", 2),
        ("grpc.http2.min_ping_interval_without_data_ms", 10_000),
        ("grpc.keepalive_permit_without_calls", 0),
        ("grpc.max_connection_idle_ms", 300_000),
        # slow loris: a connection must finish its (TLS and HTTP/2) handshake in
        # 10 s, and no connection lives past 30 min (+30 s grace for its calls).
        ("grpc.server_handshake_timeout_ms", 10_000),
        ("grpc.max_connection_age_ms", 1_800_000),
        ("grpc.max_connection_age_grace_ms", 30_000),
    ]


def start_grpc(collector: OtlpCollector, host: str, port: int, **kw: Any) -> tuple[Any, int]:
    """A started ``grpc.Server`` and its bound port; ``server.stop(None)`` ends it."""
    try:
        import grpc
    except ImportError as exc:  # pragma: no cover - the extra is installed in CI
        raise SystemExit(EXTRA_HINT) from exc
    token = kw.get("token")
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="otlp-grpc"),
        options=options(kw.get("max_bytes", 16 << 20)),
        maximum_concurrent_rpcs=MAX_RPCS,
    )
    for service, route in SERVICES.items():
        handlers = {"Export": _method(grpc, collector, route, token)}
        server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(service, handlers),))
    address = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    tls = kw.get("tls")
    if tls:
        bound = server.add_secure_port(address, grpc.ssl_server_credentials([tls]))
    else:
        bound = server.add_insecure_port(address)
    if not bound:
        raise SystemExit(f"cannot bind OTLP/gRPC on {address}")
    server.start()
    return server, bound


def read_token(path: str | None) -> bytes | None:
    if not path:
        return None
    token = Path(path).read_bytes().strip()
    printable = all(0x21 <= byte <= 0x7E for byte in token)
    if len(token) < 16 or len(token) > 4096 or not printable:
        raise SystemExit("--otlp-token-file must hold one printable token of 16..4096 bytes")
    return token


def sweep_until(collector: OtlpCollector, stop: threading.Event) -> None:
    interval = max(0.05, min(1.0, collector.idle / 2))
    while not stop.wait(interval):
        collector.flush_idle()


__all__ = ["EXTRA_HINT", "SERVICES", "options", "read_token", "response", "start_grpc"]
