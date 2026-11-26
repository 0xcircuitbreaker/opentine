"""Merkle trees, sample sizes and seeded samples for RL-scale capture audits (0.84).

* :class:`Tree`: an in-memory RFC 6962 tree over leaf hashes. It answers
  :func:`opentine.repository._tlog_proof.inclusion_proof` like a tiled log does,
  so segment proofs are RFC 9162 inclusion proofs, checked with
  :func:`opentine.repository._tlog_proof.verify_inclusion`.
* :func:`sample_size`: the smallest sample ``n`` such that, when more than
  ``floor(max_bad * N)`` of ``N`` episodes are tampered with or missing, a
  uniform sample of ``n`` without replacement misses all of them with
  probability at most ``1 - confidence``. The probability is the exact
  hypergeometric term ``P(0 bad) = prod_{i<n} (N - b - i) / (N - i)`` with
  ``b = floor(max_bad * N) + 1`` (more bad episodes only lower it), computed in
  integers, so the bound holds without floating-point slack.
* :func:`sample`: ``n`` distinct positions in ``[0, N)`` drawn by Floyd's
  algorithm from SHA-256 of the seed, each draw uniform by rejection.
"""

from __future__ import annotations

import hashlib
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from typing import Any

from opentine.repository._tlog import _node, leaf_hash, merkle_root
from opentine.repository._tlog_proof import _split

MAX_SAMPLE = 1_000_000


class Tree:
    """Subtree hashes of the full binary subtrees over ``leaves`` (32-byte leaf hashes)."""

    def __init__(self, leaves: list[bytes]) -> None:
        self.size = len(leaves)
        self._levels = [leaves]
        while len(self._levels[-1]) > 1:
            row = self._levels[-1]
            self._levels.append([_node(row[i], row[i + 1]) for i in range(0, len(row) - 1, 2)])

    def range(self, lo: int, hi: int) -> bytes:
        """RFC 6962 MTH of leaves ``[lo, hi)``."""
        n = hi - lo
        if n <= 0 or lo < 0 or hi > self.size:
            raise ValueError("hash range is out of bounds")
        if n & (n - 1) == 0 and lo % n == 0:
            height = n.bit_length() - 1
            return self._levels[height][lo >> height]
        k = _split(n)
        return _node(self.range(lo, lo + k), self.range(lo + k, hi))

    def root(self) -> bytes:
        return self.range(0, self.size) if self.size else merkle_root([])


def episode_leaf(line: bytes) -> bytes:
    """The leaf hash of one stored episode line (no trailing newline)."""
    return leaf_hash(line)


def fraction(text: Any, name: str, *, low_open: bool) -> Fraction:
    """A decimal string in ``(0, 1)`` (``[0, 1)`` unless *low_open*) as an exact fraction."""
    try:
        value = Fraction(Decimal(str(text)))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{name} {text!r} is not a decimal number") from exc
    if not (0 < value < 1 if low_open else 0 <= value < 1):
        raise ValueError(f"{name} {text} must lie in {'(0' if low_open else '[0'}, 1)")
    return value


def sample_size(population: int, confidence: Fraction, max_bad: Fraction) -> dict[str, Any]:
    """``{"sample", "tolerated", "threshold", "miss_probability"}`` for a guarantee."""
    if population < 0:
        raise ValueError("population is negative")
    tolerated = int(max_bad * population)  # floor: max_bad >= 0
    threshold = tolerated + 1  # the fewest bad episodes the guarantee must catch
    alpha = 1 - confidence
    if threshold > population:  # no violation is possible: nothing to sample
        return {"sample": 0, "tolerated": tolerated, "threshold": threshold,
                "miss_probability": 0.0}  # fmt: skip
    num = den = 1
    n = 0
    while num * alpha.denominator > alpha.numerator * den:
        if n >= MAX_SAMPLE:
            raise ValueError(f"the guarantee needs more than {MAX_SAMPLE} samples")
        num *= population - threshold - n
        den *= population - n
        n += 1
    return {"sample": n, "tolerated": tolerated, "threshold": threshold,
            "miss_probability": float(Fraction(num, den))}  # fmt: skip


def _below(seed: bytes, draw: int, bound: int) -> int:
    limit = (1 << 256) - (1 << 256) % bound
    for attempt in range(1 << 16):
        raw = hashlib.sha256(seed + draw.to_bytes(8, "big") + attempt.to_bytes(4, "big"))
        value = int.from_bytes(raw.digest(), "big")
        if value < limit:
            return value % bound
    raise ValueError("sampler exhausted its attempts")  # probability below 2**-65536


def sample(seed_hex: str, population: int, n: int) -> list[int]:
    """``n`` distinct positions in ``[0, population)``, sorted, from the seed alone."""
    if not 0 <= n <= population:
        raise ValueError("sample size is out of range")
    seed = bytes.fromhex(seed_hex)
    chosen: set[int] = set()
    for draw, j in enumerate(range(population - n, population)):
        pick = _below(seed, draw, j + 1)
        chosen.add(j if pick in chosen else pick)
    return sorted(chosen)


def positions_digest(positions: list[int]) -> str:
    text = ",".join(str(p) for p in positions).encode("ascii")
    return "sha256:" + hashlib.sha256(text).hexdigest()


__all__ = ["MAX_SAMPLE", "Tree", "episode_leaf", "fraction", "positions_digest", "sample",
           "sample_size"]  # fmt: skip
