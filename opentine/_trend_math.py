"""Arithmetic for ``tine trends`` that a browser recomputes bit for bit (0.72).

Python's ``math`` and ``random`` and a browser's ``Math`` do not promise the
same bits, so everything a trends number rests on uses only operations both
define exactly: integers, and IEEE-754 double ``+ - * /`` and comparisons.

* :class:`SplitMix`: SplitMix64 seeded with FNV-1a 64 of a UTF-8 stream name;
  ``randrange(n)`` rejects draws at or above the largest multiple of n.
* :func:`exp` and :func:`log`: range reduction by powers of two and a fixed
  number of series terms, so every step is a basic double operation.
* :func:`fit`: a logistic ``p = 1 / (1 + exp(-(a + b*x)))`` over binned
  successes by Newton steps from ``(0, 0)``, at most :data:`STEPS` of them.
* :func:`x50`: the 50% crossing ``-a/b`` and its delta-method standard error
  from the inverse information matrix, for a studentized bootstrap.
* :func:`micro_text`: a double as a six-place decimal, ``floor(v*1e6 + 0.5)``.

``opentine/data/trends/recompute.mjs`` is the same code in JavaScript; the
tests run both on the same export and compare the bytes.
"""

from __future__ import annotations

from typing import Any

MASK = (1 << 64) - 1
LN2_HI = 6.93147180369123816490e-01
LN2_LO = 1.90821492927058770002e-10
INV_LN2 = 1.44269504088896338700e00
SQRT2 = 1.41421356237309514547
STEPS = 60
SQRT_STEPS = 8
EXP_TERMS = 18
LOG_TERMS = 30


def fnv1a64(text: str) -> int:
    value = 0xCBF29CE484222325
    for byte in text.encode("utf-8"):
        value = ((value ^ byte) * 0x100000001B3) & MASK
    return value


class SplitMix:
    """SplitMix64; ``randrange`` is all the 0.57 bootstrap asks of an rng."""

    def __init__(self, stream: str) -> None:
        self.state = fnv1a64(stream)

    def next64(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
        return z ^ (z >> 31)

    def randrange(self, n: int) -> int:
        limit = (1 << 64) - (1 << 64) % n
        while True:
            draw = self.next64()
            if draw < limit:
                return draw % n


def _pow2(value: float, k: int) -> float:
    while k > 0:
        value, k = value * 2.0, k - 1
    while k < 0:
        value, k = value * 0.5, k + 1
    return value


def _floor(value: float) -> float:
    whole = float(int(value))
    return whole - 1.0 if whole > value else whole


def exp(x: float) -> float:
    if x != x:
        return x
    if x > 709.0:
        return float("inf")
    if x < -745.0:
        return 0.0
    k = _floor(x * INV_LN2 + 0.5)
    r = (x - k * LN2_HI) - k * LN2_LO
    term, total = 1.0, 1.0
    for i in range(1, EXP_TERMS):
        term = term * r / i
        total = total + term
    return _pow2(total, int(k))


def log(x: float) -> float:
    if not x > 0.0 or x == float("inf"):
        raise ValueError("log needs a positive finite number")
    e, m = 0, x
    while m >= 2.0:
        m, e = m * 0.5, e + 1
    while m < 1.0:
        m, e = m * 2.0, e - 1
    if m > SQRT2:
        m, e = m * 0.5, e + 1
    f = (m - 1.0) / (m + 1.0)
    f2, term, total = f * f, f, 0.0
    for i in range(LOG_TERMS):
        total = total + term / (2 * i + 1)
        term = term * f2
    return e * LN2_HI + (2.0 * total + e * LN2_LO)


def _sigmoid(z: float) -> float:
    return 1.0 / (1.0 + exp(-z))


def fit(bins: list[tuple[float, int, int]]) -> tuple[float, ...] | None:
    """``(a, b, haa, hab, hbb)`` for bins of ``(x, tries, successes)``: the estimate and
    the information matrix at the last step; ``None`` when it does not settle."""
    a, b = 0.0, 0.0
    for _ in range(STEPS):
        ga = gb = haa = hab = hbb = 0.0
        for x, tries, wins in bins:
            p = _sigmoid(a + b * x)
            w = tries * p * (1.0 - p)
            resid = wins - tries * p
            ga, gb = ga + resid, gb + x * resid
            haa, hab, hbb = haa + w, hab + w * x, hbb + w * x * x
        det = haa * hbb - hab * hab
        if not det > 1e-12:
            return None
        da = (hbb * ga - hab * gb) / det
        db = (haa * gb - hab * ga) / det
        a, b = a + da, b + db
        if not (abs(a) < 1e6 and abs(b) < 1e6):
            return None
        if abs(da) + abs(db) < 1e-10:
            return a, b, haa, hab, hbb
    return None


def sqrt(value: float) -> float:
    """Square root by bisection on the exponent, then Newton steps (basic operations only)."""
    if not value > 0.0:
        return 0.0
    guess = 1.0
    while guess * guess < value:
        guess = guess * 2.0
    while guess * guess > value * 4.0:
        guess = guess * 0.5
    for _ in range(SQRT_STEPS):
        guess = 0.5 * (guess + value / guess)
    return guess


def x50(params: tuple[float, ...] | None) -> tuple[float, float] | None:
    """The log2 length where the fit crosses 50% and its delta-method standard error;
    ``None`` unless success falls with length."""
    if params is None or not params[1] < 0.0:
        return None
    a, b, haa, hab, hbb = params
    det = haa * hbb - hab * hab
    point = -a / b
    var = (hbb - 2.0 * point * hab + point * point * haa) / det / (b * b)
    return point, sqrt(var)


def micro_text(value: float) -> str:
    """*value* as a decimal with six places: ``floor(value * 1e6 + 0.5)`` micro-units."""
    units = int(_floor(value * 1e6 + 0.5))
    sign, units = ("-", -units) if units < 0 else ("", units)
    return f"{sign}{units // 1_000_000}.{units % 1_000_000:06d}"


def quantile_index(alpha: Any, resamples: int) -> tuple[int, int]:
    """The 0.57 interval positions: ``floor(alpha/2*R)`` and ``ceil((1-alpha/2)*R) - 1``."""
    num, den = alpha.numerator, alpha.denominator
    low = (num * resamples) // (2 * den)
    high = -((-(2 * den - num) * resamples) // (2 * den)) - 1
    return low, high


__all__ = [
    "SplitMix",
    "exp",
    "fit",
    "fnv1a64",
    "log",
    "micro_text",
    "quantile_index",
    "sqrt",
    "x50",
]
