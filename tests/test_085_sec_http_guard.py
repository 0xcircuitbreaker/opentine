"""Security pass: the HTTP servers bound slow and idle clients (slowloris)."""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _http_guard


def _witness(tmp_path) -> Any:
    from opentine import _witness_http

    key = Ed25519PrivateKey.generate()
    return _witness_http.make_server(("127.0.0.1", 0), {}, key, "w", tmp_path / "s")


def _ui(tmp_path) -> Any:
    from opentine._ui_server import Catalog, make_server

    return make_server(Catalog([]))


def _mcp(tmp_path) -> Any:
    from opentine import _mcp_proxy_http
    from opentine._mcp_proxy_record import McpRecorder

    return _mcp_proxy_http.McpHttpProxy(("127.0.0.1", 0), "http://127.0.0.1:9/",
                                        McpRecorder.__new__(McpRecorder))  # fmt: skip


def _record(tmp_path) -> Any:
    from opentine._record_proxy import RecordingServer

    return RecordingServer({}, lambda _record: None)


def _otlp(tmp_path) -> Any:
    from opentine._otlp_http import OtlpServer

    collector = type("C", (), {"idle": 3600.0, "flush_idle": lambda self: None})()
    return OtlpServer(("127.0.0.1", 0), collector, 1024)


SERVERS: list[Callable[[Any], Any]] = [_witness, _ui, _mcp, _record, _otlp]


def _until(check: Callable[[], bool]) -> bool:
    for _ in range(10_000):  # a bound on polls, not a wall-clock threshold
        if check():
            return True
        threading.Event().wait(0.01)
    return False


def _free(server: Any) -> int:
    return server.slots._value  # noqa: SLF001


@pytest.mark.parametrize("build", SERVERS)
def test_every_server_has_a_timeout_a_deadline_and_a_cap(tmp_path, build):
    server = build(tmp_path)
    try:
        assert isinstance(server, _http_guard.GuardedHTTPServer)
        assert issubclass(server.RequestHandlerClass, _http_guard.GuardedHandler)
        assert server.timeout_s > 0 and server.daemon_threads
        assert _free(server) == server.max_clients
    finally:
        server.server_close()


@pytest.mark.parametrize("build", [_witness, _ui])
def test_a_client_dripping_its_headers_is_dropped_at_the_deadline(tmp_path, build):
    server = build(tmp_path)
    now = [0.0]
    server.monotonic = lambda: now[0]
    server.timeout_s = 3600.0  # the per-read socket timeout never fires: only the deadline can
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=60) as sock:
            sock.sendall(b"GET /health HTTP/1.1\r\n")
            assert _until(lambda: _free(server) < server.max_clients)
            now[0] = server.timeout_s + 1  # the whole-request budget is spent
            try:
                sock.sendall(b"Host: x\r\n")
                assert sock.recv(4096) == b""
            except (ConnectionResetError, BrokenPipeError):
                pass
        assert _until(lambda: _free(server) == server.max_clients)
    finally:
        server.shutdown()
        server.server_close()


def test_connections_over_the_cap_are_answered_503(tmp_path):
    server = _witness(tmp_path)
    server.timeout_s = 3600.0
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    held = []
    try:
        for _ in range(server.max_clients):
            sock = socket.create_connection(("127.0.0.1", port), timeout=60)
            sock.sendall(b"GET /health HTTP/1.1\r\n")
            held.append(sock)
        assert _until(lambda: _free(server) == 0)
        with socket.create_connection(("127.0.0.1", port), timeout=60) as extra:
            extra.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            assert extra.recv(4096).startswith(b"HTTP/1.0 503")
    finally:
        for sock in held:
            sock.close()
        server.shutdown()
        server.server_close()
