"""Per-client backoff after repeated authentication failures, and generic 500s.

A client could guess bearer tokens as fast as the server answered 401s. After
``free_failures`` consecutive failures a client is now locked out for a delay
that doubles with each further failure (capped at ``max_delay``) and gets 429
with ``Retry-After`` -- without its credentials being checked -- until the delay
passes. A success clears the record. Clients are keyed by peer address.

A 500 used to name the exception class to the caller; it now says only
``internal`` with a request id, and the exception is logged server-side.
"""

from __future__ import annotations

import logging
import math
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable

LOG = logging.getLogger("opentine.remote")


class AuthThrottle:
    def __init__(
        self,
        *,
        free_failures: int = 5,
        base_delay: float = 1.0,
        max_delay: float = 300.0,
        max_clients: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.free_failures = free_failures
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_clients = max_clients
        self.clock = clock
        self._lock = threading.Lock()
        #: client -> (consecutive failures, locked until)
        self._clients: OrderedDict[str, tuple[int, float]] = OrderedDict()

    def retry_after(self, client: str) -> int:
        """Seconds the client must still wait, or 0 if it may try now."""
        with self._lock:
            _, until = self._clients.get(client, (0, 0.0))
        remaining = until - self.clock()
        return math.ceil(remaining) if remaining > 0 else 0

    def failed(self, client: str) -> None:
        with self._lock:
            count, _ = self._clients.pop(client, (0, 0.0))
            count += 1
            excess = count - self.free_failures
            delay = 0.0
            if excess >= 0:
                delay = min(self.max_delay, self.base_delay * 2 ** min(excess, 32))
            self._clients[client] = (count, self.clock() + delay)
            while len(self._clients) > self.max_clients:
                self._clients.popitem(last=False)

    def succeeded(self, client: str) -> None:
        with self._lock:
            self._clients.pop(client, None)


def internal_error(exc: BaseException) -> dict[str, str]:
    """Log ``exc`` with a fresh request id and return the body a caller may see."""
    request_id = uuid.uuid4().hex
    LOG.error("request %s failed", request_id, exc_info=(type(exc), exc, exc.__traceback__))
    return {"error": "internal", "request_id": request_id}
