"""The only network code of the TUF client: one bounded HTTPS GET.

``urllib`` with a timeout, no proxy environment, no redirects and a hard size
limit. A 403/404 is "absent" (``None``), which is how a root chain walk ends
(object stores answer 403 for a missing key). Tests set ``FETCH`` to a callable
``(url, limit) -> bytes | None`` that serves fixture metadata from a dict.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any

TIMEOUT_SECONDS = 30.0
#: Per-address connect budget, so an unroutable IPv6 address costs seconds, not the
#: whole timeout, before the next address is tried.
CONNECT_SECONDS = 5.0
#: Test override: ``(url, limit) -> bytes | None``; ``None`` means the network.
FETCH: Any = None

__all__ = ["FETCH", "FetchError", "fetch"]


class FetchError(ValueError):
    """A repository request failed."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _dial(host: str, port: int, timeout: float) -> socket.socket:
    """Connect to each resolved address in turn, IPv4 first, each with a short budget."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    infos.sort(key=lambda info: info[0] != socket.AF_INET)
    error: OSError = OSError(f"{host}: no addresses")
    for family, kind, proto, _, address in infos:
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(min(CONNECT_SECONDS, timeout))
            sock.connect(address)
        except OSError as exc:
            sock.close()
            error = exc
            continue
        sock.settimeout(timeout)
        return sock
    raise error


class _Connection(http.client.HTTPSConnection):
    def connect(self) -> None:
        sock = _dial(self.host, self.port, TIMEOUT_SECONDS)
        self.sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)


class _Https(urllib.request.HTTPSHandler):
    def https_open(self, req: Any) -> Any:
        return self.do_open(_Connection, req)


def fetch(url: str, limit: int) -> bytes | None:
    """GET *url*; ``None`` if absent; ``FetchError`` past *limit* bytes or on failure."""
    if FETCH is not None:
        data = FETCH(url, limit)
    else:
        if not url.startswith("https://"):
            raise FetchError("TUF repositories must be reached over https://")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect, _Https)
        request = urllib.request.Request(url, headers={"User-Agent": "opentine-tuf"})
        try:
            with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                data = response.read(limit + 1)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 404):
                return None
            raise FetchError(f"{url}: HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise FetchError(f"{url}: {exc}") from None
    if data is not None and len(data) > limit:
        raise FetchError(f"{url}: response exceeds {limit} bytes")
    return data
