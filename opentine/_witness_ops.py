"""Operator support for ``tine witness serve`` (0.47, the hosted trust network).

A witness that others pin must stay up, keep its state across restarts, rotate
its key without a gap and shed abusive clients. :class:`Operator` holds what
the HTTP handler (:mod:`opentine._witness_http`) needs for that:

* **persistence:** the per-origin state (the last cosigned checkpoint) lives in
  ``--state`` and is written atomically under a lock before a cosignature is
  returned, so a restart never forgets what it signed (the split-view guard);
  :meth:`Operator.health` reads it back, and refuses to report healthy when the
  directory cannot be written.
* **key rotation:** every ``--key`` cosigns (the first is the current key), so
  an operator adds the next key, waits until verifiers pin both vkeys
  (``GET /keys`` lists them, current first), then drops the old one. No
  checkpoint is ever left with only an unpinned cosignature.
* **rate limits:** a token bucket per client address (``--rate-limit`` requests
  per minute, a burst of the same size; 0 turns it off). An empty bucket is
  ``429`` with ``Retry-After``; at most :data:`MAX_CLIENTS` buckets are kept.
* **health:** ``GET /health`` is ``200`` JSON ``{"status": "ok", "witness",
  "keys", "logs": {origin: size}, "uptime_seconds", "requests"}`` (``503`` with
  ``"status": "degraded"`` when the state directory is not writable). It never
  names a local path.
"""

from __future__ import annotations

import os
import threading
import time
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any

from opentine.repository._tlog_cosign import witness_vkey

MAX_CLIENTS = 4096


class RateLimiter:
    """A per-client token bucket: *per_minute* tokens a minute, as large a burst."""

    def __init__(self, per_minute: int, *, clock=time.monotonic):
        if per_minute < 0:
            raise ValueError("a rate limit is 0 (off) or more requests per minute")
        self.rate, self.clock = per_minute / 60.0, clock
        self.capacity = float(per_minute)
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, client: str) -> float:
        """0.0 when *client* may proceed, else the seconds until it may."""
        if self.rate == 0:
            return 0.0
        with self._lock:
            now = self.clock()
            tokens, then = self._buckets.pop(client, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - then) * self.rate)
            wait = 0.0 if tokens >= 1 else (1 - tokens) / self.rate
            self._buckets[client] = (tokens - 1 if wait == 0 else tokens, now)
            while len(self._buckets) > MAX_CLIENTS:
                self._buckets.popitem(last=False)
            return wait


class Operator:
    def __init__(self, keys: list[Any], name: str, logs: dict[str, str], state: Path, *,
                 rate_limit: int = 60, clock=time.monotonic):  # fmt: skip
        if not keys:
            raise ValueError("a witness needs at least one key")
        self.keys, self.name, self.logs, self.state = list(keys), name, logs, Path(state)
        self.limiter = RateLimiter(rate_limit, clock=clock)
        self.started, self.clock = clock(), clock
        self.requests: Counter[str] = Counter()
        self._lock = threading.Lock()

    def count(self, outcome: str) -> None:
        with self._lock:
            self.requests[outcome] += 1

    def vkeys(self) -> list[str]:
        return [witness_vkey(self.name, k.public_key().public_bytes_raw()) for k in self.keys]

    def _sizes(self) -> dict[str, int]:
        from opentine._witness_http import stored_size

        sizes = {}
        for origin, vkey in sorted(self.logs.items()):
            try:
                sizes[origin] = stored_size(self.state, origin, vkey)
            except (OSError, ValueError):
                sizes[origin] = -1  # unreadable state: reported, never guessed
        return sizes

    def writable(self) -> bool:
        try:
            self.state.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        return os.access(self.state, os.W_OK)

    def health(self) -> tuple[int, dict[str, Any]]:
        sizes = self._sizes()
        ok = self.writable() and all(size >= 0 for size in sizes.values())
        with self._lock:
            requests = dict(sorted(self.requests.items()))
        body = {"status": "ok" if ok else "degraded", "witness": self.name, "keys": self.vkeys(),
                "logs": sizes, "uptime_seconds": int(self.clock() - self.started),
                "requests": requests}  # fmt: skip
        return (200 if ok else 503), body


__all__ = ["MAX_CLIENTS", "Operator", "RateLimiter"]
