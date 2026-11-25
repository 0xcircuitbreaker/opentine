"""Binomial confidence intervals for collusion-protocol detection rates (0.83).

``wilson(k, n, alpha)`` and ``clopper_pearson(k, n, alpha)`` return two-sided
``1 - alpha`` intervals for a rate of ``k`` events in ``n`` trials as six-place
decimal strings, rounded outward (the lower bound down, the upper bound up), so
a recorded bound is never tighter than the exact one. Clopper-Pearson is found
by bisection on the binomial tail in log space (standard library only).
"""

from __future__ import annotations

import math
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal
from statistics import NormalDist

_PLACES = Decimal("0.000001")


def _bound(value: float, rounding: str) -> str:
    number = Decimal(repr(min(1.0, max(0.0, value)))).quantize(_PLACES, rounding=rounding)
    return f"{number:f}"


def _check(k: int, n: int, alpha: float) -> None:
    if isinstance(k, bool) or isinstance(n, bool) or not 0 <= k <= n:
        raise ValueError("a rate needs 0 <= k <= n")
    if not 0 < alpha < 1:
        raise ValueError("alpha must be strictly between 0 and 1")


def wilson(k: int, n: int, alpha: float) -> list[str] | None:
    """The Wilson score interval, or ``None`` when there are no trials."""
    _check(k, n, alpha)
    if n == 0:
        return None
    z = NormalDist().inv_cdf(1 - alpha / 2)
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z / (1 + z * z / n) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [_bound(centre - half, ROUND_FLOOR), _bound(centre + half, ROUND_CEILING)]


def _log_pmf(i: int, n: int, p: float) -> float:
    return (math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
            + i * math.log(p) + (n - i) * math.log1p(-p))  # fmt: skip


def _upper_tail(k: int, n: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p), 0 < p < 1."""
    return min(1.0, sum(math.exp(_log_pmf(i, n, p)) for i in range(k, n + 1)))


def _solve(target: float, f, increasing: bool) -> float:
    lo, hi = 0.0, 1.0
    for _ in range(80):
        mid = (lo + hi) / 2
        if (f(mid) < target) == increasing:
            lo = mid
        else:
            hi = mid
    return lo if increasing else hi


def clopper_pearson(k: int, n: int, alpha: float) -> list[str] | None:
    """The exact (Clopper-Pearson) interval, or ``None`` when there are no trials."""
    _check(k, n, alpha)
    if n == 0:
        return None
    half = alpha / 2
    # Lower: the p at which P(X >= k) = alpha/2 (increasing in p).
    lower = 0.0 if k == 0 else _solve(half, lambda p: _upper_tail(k, n, p), True)
    # Upper: the p at which P(X <= k) = alpha/2 (decreasing in p).
    upper = 1.0 if k == n else _solve(half, lambda p: 1 - _upper_tail(k + 1, n, p), False)
    return [_bound(lower, ROUND_FLOOR), _bound(upper, ROUND_CEILING)]


__all__ = ["clopper_pearson", "wilson"]
