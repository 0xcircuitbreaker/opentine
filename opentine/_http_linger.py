"""A lingering close for the package's HTTP servers.

A server that answers and then closes while the client's request body is still
unread makes the kernel send RST; the client can then see a reset (Windows:
WinError 10053) before it reads the reply. :class:`LingeringCloseMixin` closes
the way a web server should: half-close the write side so the reply is flushed,
read and discard what the client is still sending (bounded in bytes and time),
then close. It never raises.
"""

from __future__ import annotations

import socket
import ssl
import time
from http.server import ThreadingHTTPServer

#: Most bytes discarded from one connection before closing anyway.
LINGER_MAX_BYTES = 1 << 20
#: Longest wait for one more chunk from the client.
LINGER_RECV_TIMEOUT = 0.5
#: Longest the whole lingering close may take.
LINGER_TOTAL = 2.0


def linger_close(request: socket.socket) -> None:
    """Half-close *request*, drain what the peer still sends (bounded), close."""
    try:
        if isinstance(request, ssl.SSLSocket):
            return  # TLS has its own close; a raw drain would read ciphertext
        request.shutdown(socket.SHUT_WR)
        deadline = time.monotonic() + LINGER_TOTAL
        left = LINGER_MAX_BYTES
        while left > 0:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            request.settimeout(min(LINGER_RECV_TIMEOUT, remaining))
            chunk = request.recv(min(65536, left))
            if not chunk:
                break
            left -= len(chunk)
    except (OSError, ValueError):
        pass
    finally:
        try:
            request.close()
        except OSError:
            pass


class LingeringCloseMixin:
    """Put before a ``socketserver`` server class: its ``shutdown_request`` lingers."""

    def shutdown_request(self, request) -> None:
        if isinstance(request, ssl.SSLSocket):
            return super().shutdown_request(request)  # type: ignore[misc]
        linger_close(request)

    def hard_close(self, request) -> None:
        """The plain close, for paths that must not wait (the accept loop)."""
        super().shutdown_request(request)  # type: ignore[misc]


class LingeringHTTPServer(LingeringCloseMixin, ThreadingHTTPServer):
    """``ThreadingHTTPServer`` with a lingering close."""


__all__ = ["LINGER_MAX_BYTES", "LingeringCloseMixin", "LingeringHTTPServer", "linger_close"]
