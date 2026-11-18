"""A reply followed by a close with the request body unread must not reset the client.

Closing a socket with unread input makes the kernel send RST, and the client can
lose the reply (Windows: WinError 10053). Every package HTTP server lingers.
"""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler
from wsgiref.simple_server import make_server

from opentine._http_linger import LINGER_MAX_BYTES, LingeringHTTPServer, linger_close

BODY = b"x" * (512 * 1024)


def _exchange(address, head: str) -> bytes:
    # A small send buffer keeps the client writing after the reply: an unread body
    # then meets the close every time instead of about one time in twenty.
    with socket.socket() as conn:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        conn.settimeout(30)
        conn.connect(address)
        conn.sendall(head.encode() + BODY)
        reply = b""
        while chunk := conn.recv(65536):
            reply += chunk
    return reply


class _Refuser(BaseHTTPRequestHandler):
    def do_POST(self):  # answers without reading the body
        self.send_response(403)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, *args):
        pass


def test_the_mixin_drains_the_body_before_it_closes():
    server = LingeringHTTPServer(("127.0.0.1", 0), _Refuser)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    head = f"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {len(BODY)}\r\n\r\n"
    try:
        for _ in range(50):
            assert _exchange(server.server_address, head).split(b" ")[1] == b"403"
    finally:
        server.shutdown()
        server.server_close()


def test_linger_close_is_bounded_and_never_raises():
    left, right = socket.socketpair()
    try:
        right.sendall(b"y" * 4096)  # less than the cap, and the peer stays open
        linger_close(left)  # returns once the per-recv wait lapses
        assert left.fileno() == -1
        linger_close(left)  # a closed socket: still no exception
    finally:
        right.close()
    assert LINGER_MAX_BYTES == 1 << 20


def test_tine_serve_refusal_reads_the_body_before_it_closes(tmp_path):
    from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
    from opentine.remote._http_server import ThreadingWSGIServer, TimeoutRequestHandler

    ids = StaticTokenIdentityProvider({"w": Identity("w", "acme", ("writer",))})
    app = server.reference_app(tmp_path, identities=ids, keys=LocalKeyProvider(b"c" * 32))
    quiet = type("_Quiet", (TimeoutRequestHandler,), {"log_message": lambda *a: None})
    httpd = make_server("127.0.0.1", 0, app, server_class=ThreadingWSGIServer, handler_class=quiet)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    head = "POST /v1/tenants/acme/invitations HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    head += "Authorization: Bearer w\r\nContent-Type: application/json\r\n"
    head += f"Content-Length: {len(BODY)}\r\n\r\n"
    try:
        for _ in range(100):  # the reset was intermittent
            status = _exchange(httpd.server_address, head).split(b" ")[1]
            assert status in (b"403", b"404")
    finally:
        httpd.shutdown()
        httpd.server_close()
