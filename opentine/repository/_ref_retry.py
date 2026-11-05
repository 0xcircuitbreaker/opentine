"""Bounded, jittered waiting for contended ref locks, and rebase-and-retry updates.

Lock contention is transient: another writer holds a ref's guard lock for the
few milliseconds of one compare-and-swap. Writers therefore wait for it, with
jittered exponential backoff, for at most :data:`LOCK_WAIT_SECONDS` before the
contention is reported (a lock that is never released -- a live owner, another
host, an unreadable stamp -- still fails, just not instantly).

A compare-and-swap *mismatch* is different: the ref moved, so the caller's
``expected_old`` is stale and blindly retrying would clobber a concurrent
update. ``update_ref`` never retries one. A caller whose update is a function
of the current value (an append) opts in with :func:`update_ref_rebase`, which
re-reads the ref and asks the caller's ``rebase`` for a fresh new value.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Iterator
from typing import TypeVar

LOCK_WAIT_SECONDS = 10.0
REBASE_ATTEMPTS = 64
_FIRST_DELAY = 0.001
_MAX_DELAY = 0.05

T = TypeVar("T")


class RefLockContended(ValueError):
    """A ref (or transaction) lock is held by another writer."""


class RefCasMismatch(ValueError):
    """A compare-and-swap found the ref at a value other than the expected one."""


def backoff(budget: float) -> Iterator[float]:
    """Jittered exponential delays that sum to at most *budget* seconds."""
    left = budget
    ceiling = _FIRST_DELAY
    while left > 0:
        delay = min(left, random.uniform(ceiling / 2, ceiling))
        left -= delay
        yield delay
        ceiling = min(ceiling * 2, _MAX_DELAY)


def retry_contended(attempt: Callable[[], T], budget: float | None = None) -> T:
    """Run *attempt*, retrying while it raises :class:`RefLockContended`."""
    delays = backoff(LOCK_WAIT_SECONDS if budget is None else budget)
    while True:
        try:
            return attempt()
        except RefLockContended:
            delay = next(delays, None)
            if delay is None:
                raise
            time.sleep(delay)


def update_ref_rebase(
    repo,
    name: str,
    rebase: Callable[[str | None], str],
    *,
    actor: str = "local",
    attempts: int = REBASE_ATTEMPTS,
) -> str:
    """Move *name* to ``rebase(current)``, re-reading and retrying on a CAS mismatch.

    *rebase* must be a pure function of the current value (it may run several
    times, and its objects should already be stored). Returns the oid written.
    """
    delays = backoff(LOCK_WAIT_SECONDS)
    for _ in range(max(1, attempts)):
        current = repo.read_ref(name)
        new_oid = rebase(current)
        try:
            repo.update_ref(name, new_oid, expected_old=current, actor=actor)
            return new_oid
        except RefCasMismatch:
            time.sleep(next(delays, 0.0))
    raise RefCasMismatch(f"ref {name!r} kept moving; gave up after {attempts} rebases")
