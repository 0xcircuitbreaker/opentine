"""X15 quota: a per-(tenant, subject) token bucket answered with ``429``.

``QuotaAdmission`` refills each bucket at ``rate`` tokens per second up to
``burst``; an admitted operation spends one token (an upload also spends one per
``bytes_per_token`` bytes). An empty bucket raises :class:`QuotaExceeded`, which
the WSGI app turns into ``429 Too Many Requests`` with ``Retry-After``.

Memory is bounded: at most ``max_keys`` buckets are tracked and the least
recently used one is evicted first. An evicted key starts again with a full
bucket, so eviction can only ever be generous, never wrongly refuse.
"""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from opentine.remote.interfaces import AdmissionPolicy, Identity


class QuotaExceeded(RuntimeError):
    """The caller's bucket is empty; retry after ``retry_after`` seconds."""

    def __init__(self, retry_after: int):
        super().__init__("quota exceeded")
        self.retry_after = max(1, int(retry_after))
        self.headers = [("Retry-After", str(self.retry_after))]


class QuotaAdmission:
    def __init__(
        self,
        *,
        rate: float = 10.0,
        burst: float = 60.0,
        bytes_per_token: int = 8 * 1024 * 1024,
        max_keys: int = 10_000,
        inner: AdmissionPolicy | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not (math.isfinite(rate) and rate > 0 and math.isfinite(burst) and burst >= 1):
            raise ValueError("quota rate must be positive and burst at least 1")
        if bytes_per_token < 1 or max_keys < 1:
            raise ValueError("quota bytes_per_token and max_keys must be positive")
        self.rate, self.burst = float(rate), float(burst)
        self.bytes_per_token, self.max_keys = bytes_per_token, max_keys
        self.inner, self.clock = inner, clock
        self._lock = threading.Lock()
        #: (tenant, subject) -> (tokens, last refill time)
        self._buckets: OrderedDict[tuple[str, str], tuple[float, float]] = OrderedDict()

    @property
    def tracked(self) -> int:
        """Buckets held now (never more than ``max_keys``)."""
        return len(self._buckets)

    def cost(self, operation: str, facts: dict[str, Any]) -> float:
        size = facts.get("bytes")
        extra = size // self.bytes_per_token if isinstance(size, int) and size > 0 else 0
        return min(self.burst, 1.0 + extra)

    def admit(self, identity: Identity, operation: str, facts: dict[str, Any]) -> None:
        tenant = str(facts.get("tenant") or identity.tenant)
        key = (tenant, identity.subject)
        need = self.cost(operation, facts)
        now = self.clock()
        with self._lock:
            tokens, last = self._buckets.pop(key, (self.burst, now))
            tokens = min(self.burst, tokens + max(0.0, now - last) * self.rate)
            if tokens < need:
                self._buckets[key] = (tokens, now)
                self._evict()
                raise QuotaExceeded(math.ceil((need - tokens) / self.rate))
            self._buckets[key] = (tokens - need, now)
            self._evict()
        if self.inner is not None:
            self.inner.admit(identity, operation, facts)

    def _evict(self) -> None:
        while len(self._buckets) > self.max_keys:
            self._buckets.popitem(last=False)
