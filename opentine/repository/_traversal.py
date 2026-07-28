"""Bounded discovered-at-enqueue graph traversal."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Iterator

from opentine.kernel import KernelError

MAX_TRAVERSAL_OBJECTS = 10_000


class TraversalQueue:
    """Deduplicate queued IDs and retain the shallowest discovered distance."""

    def __init__(
        self,
        values: Iterable[tuple[str, int]] = (),
        *,
        limit: int = MAX_TRAVERSAL_OBJECTS,
    ):
        if type(limit) is not int or limit < 1:
            raise ValueError("traversal limit must be a positive integer")
        self.limit = limit
        self._queue: deque[tuple[str, int]] = deque()
        self._best: dict[str, int] = {}
        self._settled: dict[str, int] = {}
        self.peak_pending = 0
        for oid, depth in values:
            self.add(oid, depth)

    def add(self, oid: str, depth: int = 0, *, front: bool = False) -> bool:
        previous = self._best.get(oid)
        if previous is not None and previous <= depth:
            return False
        if previous is None and len(self._best) >= self.limit:
            raise KernelError("graph traversal exceeds maximum object count")
        self._best[oid] = depth
        operation = self._queue.appendleft if front else self._queue.append
        operation((oid, depth))
        self.peak_pending = max(self.peak_pending, len(self._queue))
        return True

    def __iter__(self) -> Iterator[tuple[str, int]]:
        while self._queue:
            oid, depth = self._queue.popleft()
            if self._best.get(oid) != depth:
                continue
            settled = self._settled.get(oid)
            if settled is not None and settled <= depth:
                continue
            self._settled[oid] = depth
            yield oid, depth
