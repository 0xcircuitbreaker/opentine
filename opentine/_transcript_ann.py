"""Nearest neighbours over transcript vectors (0.74, release 0.73.0).

Exact by default: with at most ``EXACT_UNDER`` vectors every vector is scored
(numpy speeds the scan when the ``embed`` extra is installed; without it the
scan is pure Python with the same results). Above that, or with ``approx``,
random-hyperplane LSH: ``TABLES`` tables of ``BITS`` sign bits each
(hyperplanes drawn from a seeded ``random.Random``), probing each table's own
bucket and the buckets one bit away; the candidates are then scored exactly.
LSH finds close neighbours (near duplicates, cosine 0.8 and up) well and weak
ones poorly, which is why behaviour triage, where similar trajectories share
only a few steps, scans exactly. When the probes find fewer than ``k``
candidates the search falls back to the exact scan, so a result is never short.

Vectors are stored as little-endian IEEE half floats (``pack``).

Scores are cosine similarities rounded to 6 places; ties order by run oid, so
the same index and query give the same answer on any machine.
"""

from __future__ import annotations

import operator
import random
import struct
from array import array
from collections import defaultdict
from collections.abc import Iterable, Sequence
from typing import Any

EXACT_UNDER = 200_000
TABLES = 8
BITS = 12
SEED = 74


def pack(vector: Sequence[float]) -> bytes:
    return struct.pack(f"<{len(vector)}e", *vector)


def unpack(raw: bytes) -> tuple[float, ...]:
    return struct.unpack(f"<{len(raw) // 2}e", raw)


def describe() -> dict[str, Any]:
    return {"lsh": "random-hyperplane", "tables": TABLES, "bits": BITS, "seed": SEED,
            "exact_under": EXACT_UNDER, "probe": "bucket and 1-bit neighbours"}  # fmt: skip


_PLANES: dict[int, list[list[list[float]]]] = {}


def planes(dim: int) -> list[list[list[float]]]:
    if dim not in _PLANES:
        rng = random.Random(f"opentine.transcripts/{SEED}/{dim}")
        _PLANES[dim] = [[[rng.gauss(0.0, 1.0) for _ in range(dim)] for _ in range(BITS)]
                        for _ in range(TABLES)]  # fmt: skip
    return _PLANES[dim]


def dot(a: Sequence[float], b: Sequence[float]) -> float:
    return sum(map(operator.mul, a, b))


def keys(vector: Sequence[float]) -> list[int]:
    """One ``BITS``-bit bucket key per table."""
    out = []
    for table in planes(len(vector)):
        key = 0
        for bit, plane in enumerate(table):
            if dot(plane, vector) >= 0.0:
                key |= 1 << bit
        out.append(key)
    return out


class Index:
    """Vectors by run oid (as 32-bit floats), with LSH buckets built on first approximate use."""

    def __init__(self, rows: Iterable[tuple[str, Sequence[float], Sequence[int] | None]]):
        self.runs: list[str] = []
        self.vectors: list[array] = []
        self.keys: list[Sequence[int] | None] = []
        for run, vector, key in rows:
            self.runs.append(run)
            self.vectors.append(array("f", vector))
            self.keys.append(key)
        self._buckets: list[dict[int, list[int]]] | None = None
        self._matrix: Any = None

    def __len__(self) -> int:
        return len(self.runs)

    def _tables(self) -> list[dict[int, list[int]]]:
        if self._buckets is None:
            self._buckets = [defaultdict(list) for _ in range(TABLES)]
            for i, vector in enumerate(self.vectors):
                for t, key in enumerate(self.keys[i] or keys(vector)):
                    self._buckets[t][key].append(i)
        return self._buckets

    def candidates(self, query: Sequence[float]) -> set[int]:
        found: set[int] = set()
        for table, key in zip(self._tables(), keys(query), strict=True):
            for probe in (key, *(key ^ (1 << b) for b in range(BITS))):
                found.update(table.get(probe, ()))
        return found

    def _scores(self, query: Sequence[float], pool: list[int]) -> list[float]:
        try:
            import numpy as np
        except ImportError:
            return [dot(query, self.vectors[i]) for i in pool]
        if self._matrix is None:
            raw = b"".join(v.tobytes() for v in self.vectors)
            self._matrix = np.frombuffer(raw, dtype=np.float32).reshape(len(self), -1)
        rows = self._matrix[np.asarray(pool, dtype=np.int64)].astype(np.float64)
        return [float(x) for x in rows @ np.asarray(query, dtype=np.float64)]

    def search(self, query: Sequence[float], k: int, *, exclude: str | None = None,
               approx: bool = False) -> dict[str, Any]:  # fmt: skip
        """``{"method", "candidates", "hits": [{"run", "score"}]}``, best first."""
        if k < 1:
            raise ValueError("k is at least 1")
        method = "exact"
        pool: list[int] = list(range(len(self)))
        if approx or len(self) > EXACT_UNDER:
            found = self.candidates(query)
            if exclude in self.runs:
                found.discard(self.runs.index(exclude))
            if len(found) >= k:
                method, pool = "lsh", sorted(found)
            else:
                method = "exact-fallback"
        pool = [i for i in pool if self.runs[i] != exclude]
        scores = self._scores(query, pool) if pool else []
        scored = [(-round(s, 6), self.runs[i]) for i, s in zip(pool, scores, strict=True)]
        scored.sort()
        hits = [{"run": run, "score": -neg} for neg, run in scored[:k]]
        count = len(scored)
        return {"method": method, "candidates": count, "hits": hits}


__all__ = ["BITS", "EXACT_UNDER", "TABLES", "Index", "describe", "dot", "keys", "pack",
           "unpack"]  # fmt: skip
