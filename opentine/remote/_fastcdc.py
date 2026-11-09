"""FastCDC content-defined chunking for large payloads in object storage (0.49).

Chunking is a *stored form*: an object's id, bytes and canonical encoding do
not change. A payload of ``CHUNK_THRESHOLD`` bytes or more is cut into chunks
whose boundaries depend on content (normalized FastCDC, gear hash), so an
edit near the start of a large transcript moves one or two chunks instead of
every fixed-size block after it. Each chunk is named by its SHA-256 and the
object is stored as a chunk manifest (``_chunk_manifest``). Readers fetch the
chunks they need, check each digest, and re-hash the whole envelope against
its oid before handing it out.

The gear table is fixed (seeded), so the same bytes always cut the same way
across processes, platforms and releases.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from dataclasses import dataclass

#: Payloads at or above this size are chunked; smaller ones are stored whole.
CHUNK_THRESHOLD = 8 * 1024 * 1024

_RNG = random.Random(49)  # one generator: a fresh one per entry gives 256 equal values
_GEAR = tuple(_RNG.getrandbits(64) for _ in range(256))
del _RNG
_M64 = (1 << 64) - 1


@dataclass(frozen=True)
class ChunkParams:
    """Normalized FastCDC bounds (bytes). ``avg_size`` must be a power of two."""

    min_size: int = 256 * 1024
    avg_size: int = 1024 * 1024
    max_size: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        avg = self.avg_size
        if avg < 64 or avg & (avg - 1):
            raise ValueError("FastCDC average chunk size must be a power of two >= 64")
        if not 0 < self.min_size <= avg <= self.max_size:
            raise ValueError("FastCDC sizes must satisfy 0 < min <= avg <= max")

    def masks(self) -> tuple[int, int]:
        bits = self.avg_size.bit_length() - 1
        hard = ((1 << (bits + 1)) - 1) << (64 - bits - 1)  # before avg: harder to cut
        easy = ((1 << (bits - 1)) - 1) << (64 - bits + 1)  # after avg: easier
        return hard, easy


DEFAULT_PARAMS = ChunkParams()


def _scan(view: memoryview, start: int, stop: int, h: int, mask: int) -> tuple[int, int]:
    """First offset past a cut in ``view[start:stop]`` (-1 when none) and the hash."""
    gear, mask64 = _GEAR, _M64
    for i in range(start, stop):
        h = ((h << 1) + gear[view[i]]) & mask64
        if not h & mask:
            return i + 1, h
    return -1, h


def boundaries(data: bytes | memoryview, params: ChunkParams = DEFAULT_PARAMS) -> Iterator[int]:
    """Chunk end offsets of *data*, in order; the last is ``len(data)``."""
    hard, easy = params.masks()
    low, avg, high = params.min_size, params.avg_size, params.max_size
    view = memoryview(data)
    start, size = 0, len(view)
    while start < size:
        end = min(size, start + high)
        if end - start <= low:
            yield end
            return
        middle = min(end, start + avg)
        cut, h = _scan(view, start + low, middle, 0, hard)
        if cut < 0:
            cut, _ = _scan(view, middle, end, h, easy)
        cut = end if cut < 0 else cut
        yield cut
        start = cut


def chunks(data: bytes, params: ChunkParams = DEFAULT_PARAMS) -> Iterator[bytes]:
    """The chunks of *data*; joined, they are *data*."""
    start = 0
    for end in boundaries(data, params):
        yield data[start:end]
        start = end
