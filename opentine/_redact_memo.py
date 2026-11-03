"""A per-save memo for the text scrubber, so a long run is not re-scanned.

A save redacts the same strings many times over: every step repeats its field
names, a step's payload is scrubbed as a value and again as the stored blob, and
long runs repeat model names, roles and tool output. ``redact_blob`` is a pure
function of its bytes -- the scan reads no policy, context or clock (the run's
``extra_secret_keys`` act only on the field walk, ``_canon_redact._redact``) -- so
a memo keyed on the exact input bytes returns exactly what the scan would have.

The memo exists only inside :func:`save_memo`, which the save paths enter; every
other caller scans as before. It holds at most ``MAX_BYTES`` of inputs and skips
values over ``MAX_VALUE``, so a huge run costs bounded memory, and it is dropped
when the save ends so no plaintext outlives the write. A stdlib-only leaf.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar

MAX_VALUE = 1 << 20
MAX_BYTES = 64 << 20


class _Memo(dict):
    size = 0


_ACTIVE: ContextVar[_Memo | None] = ContextVar("opentine_redact_memo", default=None)


def active() -> _Memo | None:
    return _ACTIVE.get()


@contextmanager
def save_memo() -> Iterator[None]:
    """Memoize ``redact_blob`` for the block (re-entrant: an outer memo is kept)."""
    if _ACTIVE.get() is not None:
        yield
        return
    token = _ACTIVE.set(_Memo())
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def cached(value: bytes, scrub: Callable[[bytes], bytes]) -> bytes:
    memo = _ACTIVE.get()
    if memo is None or type(value) is not bytes or len(value) > MAX_VALUE:
        return scrub(value)
    hit = memo.get(value)
    if hit is None:
        hit = scrub(value)
        if memo.size + len(value) <= MAX_BYTES:
            memo[value] = hit
            memo.size += len(value)
    return hit


__all__ = ["active", "cached", "save_memo"]
