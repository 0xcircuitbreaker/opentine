"""The reference remote's bounded threading HTTP server.

Each connection holds one of ``max_workers`` slots for at most
``request_deadline`` seconds. That alone let anyone who can connect hold every
slot: sixteen idle sockets, re-opened as each deadline expired, kept a request
from ever being served, while ``process_request`` blocked the accept loop
waiting for a slot. Now:

* a connection that has not finished its TLS handshake, request line and headers
  within ``header_timeout`` seconds is closed (a byte every few seconds no longer
  keeps it alive -- the socket timeout is per read, this deadline is not);
* one peer address holds at most ``max_per_peer`` slots (half by default);
* when no slot is free the connection is answered ``503`` and closed at once
  (closed, over TLS, where a reply needs a handshake), never queued behind the
  accept loop.

Request logs name the method and path without query strings, and never the
resumable upload ids that let a same-tenant writer reach someone else's upload.
"""

from __future__ import annotations

import re
import socket
import ssl
import threading
from collections import Counter
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer

_BUSY_BODY = b'{"error":"server is busy"}'
_BUSY = (
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n"
    b"Content-Length: %d\r\nRetry-After: 1\r\nConnection: close\r\n\r\n" % len(_BUSY_BODY)
) + _BUSY_BODY
_UPLOAD_PATH = re.compile(r"/packs/[^/?]+")


def _peer(address) -> str:
    return str(address[0]) if isinstance(address, tuple) and address else str(address)


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    request_queue_size = 64
    max_workers = 16
    #: Slots one peer address may hold; ``None`` is half of ``max_workers``.
    max_per_peer: int | None = None
    request_deadline = 60
    ssl_context: ssl.SSLContext | None = None

    def __init__(self, *args, **kwargs):
        self._request_slots = threading.BoundedSemaphore(self.max_workers)
        self._peers: Counter[str] = Counter()
        self._peers_guard = threading.Lock()
        super().__init__(*args, **kwargs)

    def _peer_limit(self) -> int:
        return self.max_per_peer or max(1, self.max_workers // 2)

    def _claim_peer(self, peer: str) -> bool:
        with self._peers_guard:
            if self._peers[peer] >= self._peer_limit():
                return False
            self._peers[peer] += 1
            return True

    def _release_peer(self, peer: str) -> None:
        guard = getattr(self, "_peers_guard", None)
        if guard is None:
            return
        with guard:
            self._peers[peer] -= 1
            if self._peers[peer] <= 0:
                del self._peers[peer]

    def _refuse(self, request) -> None:
        """Answer 503 and close, without ever blocking the accept loop."""
        try:
            if not isinstance(request, ssl.SSLSocket):  # a TLS reply needs a handshake
                request.settimeout(0.5)
                request.sendall(_BUSY)
        except OSError:
            pass
        self.shutdown_request(request)

    def process_request(self, request, client_address) -> None:
        peer = _peer(client_address)
        if not self._claim_peer(peer):
            return self._refuse(request)
        if not self._request_slots.acquire(blocking=False):
            self._release_peer(peer)
            return self._refuse(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            self._release_peer(peer)
            raise

    def get_request(self):
        request, address = super().get_request()
        if self.ssl_context is None:
            return request, address
        try:
            wrapped = self.ssl_context.wrap_socket(
                request, server_side=True, do_handshake_on_connect=False
            )
        except BaseException:
            request.close()
            raise
        return wrapped, address

    def process_request_thread(self, request, client_address) -> None:
        def expire() -> None:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        deadline = threading.Timer(self.request_deadline, expire)
        deadline.daemon = True
        deadline.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            deadline.join()
            self._request_slots.release()
            self._release_peer(_peer(client_address))


class TimeoutRequestHandler(WSGIRequestHandler):
    #: Per-connection inactivity timeout; the server also has an absolute deadline.
    timeout = 30
    #: Total seconds for the TLS handshake, request line and headers.
    header_timeout = 10

    def setup(self) -> None:
        super().setup()
        self._header_timer = threading.Timer(self.header_timeout, self._expire_headers)
        self._header_timer.daemon = True
        self._header_timer.start()

    def _expire_headers(self) -> None:
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def parse_request(self) -> bool:
        try:
            return super().parse_request()
        finally:
            self._header_timer.cancel()

    def finish(self) -> None:
        timer = getattr(self, "_header_timer", None)
        if timer is not None:
            timer.cancel()
        super().finish()

    def log_request(self, code="-", size="-") -> None:
        path = _UPLOAD_PATH.sub("/packs/<upload>", str(getattr(self, "path", "")).split("?")[0])
        self.log_message('"%s %s" %s %s', getattr(self, "command", "-"), path, code, size)
