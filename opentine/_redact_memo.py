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
when the save ends so no plaintext outlives the write.

Outside a save (a live recorder appending one event at a time, an importer)
the scan falls back to a process-wide bounded LRU keyed by the SHA-256 of the
input. It holds digests and *redacted* outputs only -- never the plaintext it
was asked to scrub -- and at most ``LRU_ENTRIES`` of them, ``LRU_BYTES`` in all.
A stdlib-only leaf.
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar

MAX_VALUE = 1 << 20
MAX_BYTES = 64 << 20
LRU_ENTRIES = 8192
LRU_BYTES = 32 << 20
#: Below this a hash costs about what the scan does on text this short.
LRU_MIN = 16


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


class _Lru:
    """Digest -> redacted output, least recently used evicted first."""

    def __init__(self) -> None:
        self.items: OrderedDict[bytes, bytes] = OrderedDict()
        self.size = 0
        self.lock = threading.Lock()

    def get(self, key: bytes) -> bytes | None:
        with self.lock:
            hit = self.items.get(key)
            if hit is not None:
                self.items.move_to_end(key)
            return hit

    def put(self, key: bytes, value: bytes) -> None:
        with self.lock:
            if key in self.items:
                return
            self.items[key] = value
            self.size += len(value)
            while len(self.items) > LRU_ENTRIES or self.size > LRU_BYTES:
                self.size -= len(self.items.popitem(last=False)[1])

    def clear(self) -> None:
        with self.lock:
            self.items.clear()
            self.size = 0


LRU = _Lru()


def _lru(value: bytes, scrub: Callable[[bytes], bytes]) -> bytes:
    if len(value) < LRU_MIN:
        return scrub(value)
    key = hashlib.sha256(value).digest()
    hit = LRU.get(key)
    if hit is None:
        hit = scrub(value)
        LRU.put(key, hit)
    return hit


def cached(value: bytes, scrub: Callable[[bytes], bytes]) -> bytes:
    if type(value) is not bytes or len(value) > MAX_VALUE:
        return scrub(value)
    memo = _ACTIVE.get()
    if memo is None:
        return _lru(value, scrub)
    hit = memo.get(value)
    if hit is None:
        hit = scrub(value)
        if memo.size + len(value) <= MAX_BYTES:
            memo[value] = hit
            memo.size += len(value)
    return hit


__all__ = ["LRU", "active", "cached", "save_memo"]
