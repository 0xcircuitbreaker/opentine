"""Paired statistics for ``tine eval compare --ci`` (0.58).

Two verified evals of the same items become an *export*: the method, the
alpha, the seed, the resample count and, per shared item, both scores and both
pass bits. :func:`compute` turns an export into per-metric deltas, intervals
and regressions; ``scripts/eval_compare_reproduce.py`` is an independent,
standard-library copy of it that reproduces the numbers exactly from the
export alone.

Everything is exact integer arithmetic over micro-units (scores carry at most
six decimal places), so the only randomness is the resampling, and that is
Python's ``random.Random`` seeded with ``"opentine-eval-compare/1:<seed>:<metric>"``
(the string seed is hashed with SHA-512 by CPython, stable across versions).

* ``paired-bootstrap``: *resamples* draws of n paired differences with
  replacement (``randrange(n)``, n times each); the interval is the
  ``floor(alpha/2 * R)``-th and ``ceil((1 - alpha/2) * R) - 1``-th of the
  sorted resampled sums, divided by n. Significant when it excludes 0.
* ``permutation``: a paired sign-flip test; each resample flips every
  difference on ``getrandbits(1)``; ``p = (k + 1) / (R + 1)`` where k counts
  resampled sums at least as far from 0 as the observed one. Significant when
  ``p < alpha``.

A metric *regresses* when its change is significant and negative. Decimals
are strings rounded half-even to six places.
"""

from __future__ import annotations

import math
import random
from decimal import ROUND_HALF_EVEN, Decimal
from fractions import Fraction
from typing import Any

CONVENTION = "opentine.eval-compare/1"
METHODS = ("paired-bootstrap", "permutation")
METRICS = ("score", "pass_rate")
MICRO = 1_000_000
DEFAULT_RESAMPLES = 2000
_PLACES = Decimal("0.000001")


def text(value: Fraction | int) -> str:
    """A fraction as a six-place decimal string, rounded half-even."""
    number = Decimal(value.numerator) / Decimal(value.denominator) if isinstance(
        value, Fraction) else Decimal(value)  # fmt: skip
    out = f"{number.quantize(_PLACES, rounding=ROUND_HALF_EVEN):f}"
    return "0.000000" if out == "-0.000000" else out


def micro(score: str) -> int:
    """A canonical verdict score (``0.25``) in micro-units (250000)."""
    return int((Decimal(score) * MICRO).to_integral_value())


def export(left: list[dict[str, Any]], right: list[dict[str, Any]], *, method: str,
           alpha: str, seed: int, resamples: int) -> dict[str, Any]:  # fmt: skip
    """The export of two verdict lists: every item both score, in item order."""
    check(method, alpha, seed, resamples)
    a = {row["item"]: row for row in left}
    b = {row["item"]: row for row in right}
    items = [{"item": item, "a": a[item]["score"], "b": b[item]["score"],
              "a_passed": a[item]["passed"], "b_passed": b[item]["passed"]}
             for item in sorted(set(a) & set(b))]  # fmt: skip
    return {"convention": CONVENTION, "method": method, "alpha": alpha, "seed": seed,
            "resamples": resamples, "items": items}  # fmt: skip


def check(method: str, alpha: str, seed: int, resamples: int) -> None:
    if method not in METHODS:
        raise ValueError(f"--ci is one of {', '.join(METHODS)}")
    try:
        number = Decimal(alpha)
    except ArithmeticError as exc:
        raise ValueError(f"--alpha {alpha!r} is not a decimal") from exc
    if not number.is_finite() or not 0 < number < 1:
        raise ValueError("--alpha must be strictly between 0 and 1")
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**63:
        raise ValueError("--seed must be an integer in 0..2^63-1")
    if isinstance(resamples, bool) or not isinstance(resamples, int):
        raise ValueError("--resamples must be an integer")
    if not 100 <= resamples <= 100_000:
        raise ValueError("--resamples must be in 100..100000")


def _bootstrap(diffs: list[int], rng: random.Random, resamples: int, alpha: Fraction) -> dict:
    n = len(diffs)
    sums = sorted(sum(diffs[rng.randrange(n)] for _ in range(n)) for _ in range(resamples))
    low = sums[math.floor(alpha / 2 * resamples)]
    high = sums[math.ceil((1 - alpha / 2) * resamples) - 1]
    lo, hi = Fraction(low, n * MICRO), Fraction(high, n * MICRO)
    return {"ci": [text(lo), text(hi)], "p_value": None, "significant": lo > 0 or hi < 0}


def _permutation(diffs: list[int], rng: random.Random, resamples: int, alpha: Fraction) -> dict:
    observed = abs(sum(diffs))
    hits = 0
    for _ in range(resamples):
        total = sum(d if rng.getrandbits(1) else -d for d in diffs)
        hits += abs(total) >= observed
    p = Fraction(hits + 1, resamples + 1)
    return {"ci": None, "p_value": text(p), "significant": p < alpha}


def compute(data: dict[str, Any]) -> dict[str, Any]:
    """Per-metric means, delta, interval or p-value, and the regressions."""
    method, alpha, seed, resamples = data["method"], data["alpha"], data["seed"], data["resamples"]
    check(method, alpha, seed, resamples)
    rows = data["items"]
    n = len(rows)
    columns = {
        "score": ([micro(r["a"]) for r in rows], [micro(r["b"]) for r in rows]),
        "pass_rate": ([MICRO * bool(r["a_passed"]) for r in rows],
                      [MICRO * bool(r["b_passed"]) for r in rows]),
    }  # fmt: skip
    level = Fraction(Decimal(alpha))
    metrics: dict[str, Any] = {}
    for name in METRICS:
        a, b = columns[name]
        diffs = [y - x for x, y in zip(a, b, strict=True)]
        delta = Fraction(sum(diffs), n * MICRO) if n else Fraction(0)
        row: dict[str, Any] = {
            "a": text(Fraction(sum(a), n * MICRO)) if n else None,
            "b": text(Fraction(sum(b), n * MICRO)) if n else None,
            "delta": text(delta),
        }
        if n:
            rng = random.Random(f"{CONVENTION}:{seed}:{name}")
            test = _bootstrap if method == "paired-bootstrap" else _permutation
            row.update(test(diffs, rng, resamples, level))
        else:
            row.update({"ci": None, "p_value": None, "significant": False})
        row["regression"] = row["significant"] and delta < 0
        row["improvement"] = row["significant"] and delta > 0
        metrics[name] = row
    return {"convention": CONVENTION, "method": method, "alpha": alpha, "seed": seed,
            "resamples": resamples, "n": n, "metrics": metrics,
            "regressions": [m for m in METRICS if metrics[m]["regression"]]}  # fmt: skip


__all__ = ["CONVENTION", "DEFAULT_RESAMPLES", "METHODS", "METRICS", "check", "compute",
           "export", "micro", "text"]  # fmt: skip
