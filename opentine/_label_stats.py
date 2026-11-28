"""Inter-rater agreement for rubric labels (0.89): Cohen, Fleiss, Krippendorff.

Every statistic is exact rational arithmetic over nominal labels, so the only
randomness is the bootstrap, which is Python's ``random.Random`` seeded with
``"opentine.label-agreement/1:<seed>:<metric>"`` (CPython hashes a string seed
with SHA-512, stable across versions). A *unit* is one item's labels.

* ``cohen`` -- two raters, units both labelled: ``(po - pe) / (1 - pe)``.
* ``fleiss`` -- every unit has the same number ``m >= 2`` of labels.
* ``krippendorff`` -- nominal alpha over every unit with at least two labels
  (any number of raters, missing labels allowed).

A statistic is *undefined* (``None``, with a ``reason``) when its denominator
is zero -- one category only, no pairable unit -- and an undefined value never
passes a floor. The interval resamples units with replacement ``resamples``
times; it is the ``floor(alpha/2 * R)``-th and ``ceil((1 - alpha/2) * R) - 1``-th
of the sorted defined resamples. When more resamples than ``floor(alpha/2 * R)``
are undefined, the interval itself is undefined.
"""

from __future__ import annotations

import math
import random
from collections import Counter
from collections.abc import Callable, Sequence
from fractions import Fraction
from typing import Any

CONVENTION = "opentine.label-agreement/1"
METRICS = ("cohen", "fleiss", "krippendorff")
MAX_RESAMPLES = 100_000

Unit = Sequence[str]
Stat = tuple[Fraction | None, str | None]


def cohen(pairs: Sequence[tuple[str, str]]) -> Stat:
    """Cohen's kappa over ``(rater A, rater B)`` label pairs."""
    n = len(pairs)
    if n == 0:
        return None, "no unit is labelled by both raters"
    left, right = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    po = Fraction(sum(1 for a, b in pairs if a == b), n)
    pe = sum((Fraction(left[c] * right[c], n * n) for c in left), Fraction(0))
    if pe == 1:
        return None, "both raters use one and the same label only (chance agreement is 1)"
    return (po - pe) / (1 - pe), None


def fleiss(units: Sequence[Unit]) -> Stat:
    """Fleiss' kappa; every unit must carry the same number of labels (at least two)."""
    if not units:
        return None, "no unit"
    m = len(units[0])
    if m < 2 or any(len(u) != m for u in units):
        return None, "units carry unequal numbers of labels (or fewer than two)"
    n = len(units)
    totals: Counter = Counter()
    agree = Fraction(0)
    for unit in units:
        counts = Counter(unit)
        totals.update(counts)
        agree += Fraction(sum(c * c for c in counts.values()) - m, m * (m - 1))
    pbar = agree / n
    pe = sum((Fraction(c, n * m) ** 2 for c in totals.values()), Fraction(0))
    if pe == 1:
        return None, "every label is the same category (chance agreement is 1)"
    return (pbar - pe) / (1 - pe), None


def krippendorff(units: Sequence[Unit]) -> Stat:
    """Krippendorff's alpha for nominal data over units with at least two labels."""
    pairable = [u for u in units if len(u) >= 2]
    if not pairable:
        return None, "no unit has two labels"
    margins: Counter = Counter()
    disagree = Fraction(0)
    for unit in pairable:
        counts, m = Counter(unit), len(unit)
        for c, nc in counts.items():
            margins[c] += nc
            for k, nk in counts.items():
                if c != k:
                    disagree += Fraction(nc * nk, m - 1)
    n = sum(margins.values())
    expected = sum(margins[c] * margins[k] for c in margins for k in margins if c != k)
    if expected == 0:
        return None, "every label is the same category (no expected disagreement)"
    return 1 - Fraction(n - 1) * disagree / expected, None


def _ci(values: list[Fraction | None], alpha: Fraction) -> dict[str, Any]:
    resamples = len(values)
    defined = sorted(v for v in values if v is not None)
    cut = math.floor(alpha / 2 * resamples)
    if not defined or resamples - len(defined) > cut:
        return {"lower": None, "upper": None, "undefined_resamples": resamples - len(defined)}
    hi = min(math.ceil((1 - alpha / 2) * len(defined)) - 1, len(defined) - 1)
    lo = min(math.floor(alpha / 2 * len(defined)), hi)
    return {"lower": defined[lo], "upper": defined[hi],
            "undefined_resamples": resamples - len(defined)}  # fmt: skip


def bootstrap(units: Sequence[Any], stat: Callable[[Sequence[Any]], Stat], *, metric: str,
              seed: int, resamples: int, alpha: Fraction) -> dict[str, Any]:  # fmt: skip
    """``{value, reason, lower, upper, undefined_resamples}`` of *stat* over *units*."""
    if not 1 <= resamples <= MAX_RESAMPLES:
        raise ValueError(f"resamples must be in 1..{MAX_RESAMPLES}")
    value, reason = stat(units)
    rng = random.Random(f"{CONVENTION}:{seed}:{metric}")
    n = len(units)
    if value is None or n == 0:
        return {"value": None, "reason": reason, "lower": None, "upper": None,
                "undefined_resamples": None}  # fmt: skip
    draws = [stat([units[rng.randrange(n)] for _ in range(n)])[0] for _ in range(resamples)]
    return {"value": value, "reason": None, **_ci(draws, alpha)}


def passes(row: dict[str, Any], floor: Fraction) -> bool:
    """A floor holds only on a defined lower bound at or above it (undefined never passes)."""
    lower = row.get("lower")
    return isinstance(lower, Fraction) and lower >= floor


__all__ = ["CONVENTION", "METRICS", "bootstrap", "cohen", "fleiss", "krippendorff", "passes"]
