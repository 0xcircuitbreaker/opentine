"""Judge-vs-human agreement (0.89): chance-corrected agreement with a bootstrap interval.

The raters of an item are its counted human labels (:mod:`opentine._rubric_labels`)
plus the judge's label. Items the judge abstained on or erred on are left out
of the statistic and counted (``abstained``, ``errored``); an item with no human
label is left out as ``unlabelled``. The statistic is:

* **Cohen's kappa** when every counted item has exactly two raters (one human
  and the judge);
* **Fleiss' kappa** when every counted item has the same number of raters, more
  than two;
* **Krippendorff's alpha** (nominal) otherwise.

The interval is a percentile bootstrap over items (``resamples`` draws, seeded,
so a report is reproducible); the *floor* is met when the interval's lower bound
(at ``alpha/2``, default 0.025, i.e. a 95% interval) is at least ``floor``
(default 0.6) and the judge decided at least ``min_coverage`` (default 0.9) of the
labelled items. A judge cannot raise its agreement by abstaining on hard items:
those items lower its coverage. A statistic that is undefined (every rater gave
one label to every item) does not meet the floor: fail closed.
"""

from __future__ import annotations

import random
from collections import Counter
from fractions import Fraction
from typing import Any

FLOOR = Fraction(3, 5)
MIN_COVERAGE = Fraction(9, 10)
DEFAULT_RESAMPLES = 2000
MAX_RESAMPLES = 100_000


def cohen(pairs: list[tuple[str, str]]) -> float | None:
    n = len(pairs)
    if n == 0:
        return None
    po = sum(a == b for a, b in pairs) / n
    left, right = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum(left[k] * right[k] for k in left) / (n * n)
    return None if pe >= 1 else (po - pe) / (1 - pe)


def fleiss(units: list[list[str]]) -> float | None:
    if not units:
        return None
    m = len(units[0])
    total = Counter(x for u in units for x in u)
    n = len(units)
    pbar = sum((sum(c * c for c in Counter(u).values()) - m) / (m * (m - 1)) for u in units) / n
    pe = sum((c / (n * m)) ** 2 for c in total.values())
    return None if pe >= 1 else (pbar - pe) / (1 - pe)


def krippendorff(units: list[list[str]]) -> float | None:
    units = [u for u in units if len(u) >= 2]
    if not units:
        return None
    coincide: Counter = Counter()
    for u in units:
        counts, m = Counter(u), len(u)
        for a in counts:
            for b in counts:
                pairs = counts[a] * (counts[b] - (a == b))
                coincide[(a, b)] += pairs / (m - 1)
    totals: Counter = Counter()
    for (a, _), v in coincide.items():
        totals[a] += v
    n = sum(totals.values())
    observed = sum(v for (a, b), v in coincide.items() if a != b)
    expected = sum(totals[a] * totals[b] for a in totals for b in totals if a != b) / (n - 1)
    return None if expected == 0 else 1 - observed / expected


def statistic(units: list[list[str]]) -> tuple[str, float | None]:
    sizes = {len(u) for u in units}
    if sizes == {2}:
        return "cohen-kappa", cohen([(u[0], u[1]) for u in units])
    if len(sizes) == 1 and sizes != {1}:
        return "fleiss-kappa", fleiss(units)
    return "krippendorff-alpha", krippendorff(units)


_BY = {"cohen-kappa": lambda us: cohen([(u[0], u[1]) for u in us]), "fleiss-kappa": fleiss,
       "krippendorff-alpha": krippendorff}  # fmt: skip


def _text(value: float | None) -> str | None:
    return None if value is None else format(value, ".6f")


def report(judge: dict[str, dict[str, Any]], humans: dict[str, dict[str, str]], *,
           floor: Fraction = FLOOR, min_coverage: Fraction = MIN_COVERAGE, seed: int = 0,
           resamples: int = DEFAULT_RESAMPLES,
           alpha: Fraction = Fraction(1, 20)) -> dict[str, Any]:  # fmt: skip
    """The agreement report; *judge* maps item to an outcome, *humans* item to labels."""
    if not 1 <= resamples <= MAX_RESAMPLES:
        raise ValueError(f"resamples is 1..{MAX_RESAMPLES}")
    if not 0 < alpha < 1 or not 0 <= floor <= 1 or not 0 <= min_coverage <= 1:
        raise ValueError("alpha is in (0, 1); floor and min_coverage in [0, 1]")
    labelled = sorted(i for i, by in humans.items() if by)
    abstained = [i for i in labelled if judge.get(i, {}).get("status") == "abstain"]
    errored = [i for i in labelled if judge.get(i, {}).get("status") not in ("label", "abstain")]
    counted = [i for i in labelled if judge.get(i, {}).get("status") == "label"]
    units = [[*(humans[i][r] for r in sorted(humans[i])), judge[i]["label"]] for i in counted]
    method, value = statistic(units)
    rng, draws = random.Random(seed), []
    for _ in range(resamples if units else 0):
        sample = [units[rng.randrange(len(units))] for _ in units]
        got = _BY[method](sample)
        draws.append(got if got is not None else float("-inf"))
    draws.sort()
    lower = draws[int(len(draws) * float(alpha / 2))] if draws else None
    upper = draws[min(len(draws) - 1, int(len(draws) * float(1 - alpha / 2)))] if draws else None
    lower = None if lower == float("-inf") else lower
    coverage = Fraction(len(counted), len(labelled)) if labelled else Fraction(0)
    reasons = []
    if value is None:
        reasons.append("agreement is undefined on these labels")
    elif lower is None:
        reasons.append("the lower bound is undefined (resamples with a single label)")
    elif lower < float(floor):
        reasons.append(f"the lower bound {_text(lower)} is below the floor {_text(float(floor))}")
    if coverage < min_coverage:
        reasons.append(f"the judge decided {len(counted)} of {len(labelled)} labelled item(s)")
    humans_only = [[humans[i][r] for r in sorted(humans[i])] for i in labelled
                   if len(humans[i]) >= 2]  # fmt: skip
    inter = statistic(humans_only) if humans_only else (None, None)
    return {"method": method, "value": _text(value), "ci": [_text(lower), _text(upper)],
            "floor": _text(float(floor)), "min_coverage": _text(float(min_coverage)),
            "coverage": _text(float(coverage)), "meets_floor": not reasons,
            "reasons": reasons, "items": len(judge), "labelled": len(labelled),
            "counted": len(counted), "abstained": abstained, "errored": errored,
            "unlabelled": sorted(set(judge) - set(labelled)),
            "human_agreement": {"method": inter[0], "value": _text(inter[1])},
            "seed": seed, "resamples": resamples, "alpha": _text(float(alpha))}  # fmt: skip


__all__ = ["FLOOR", "MIN_COVERAGE", "cohen", "fleiss", "krippendorff", "report", "statistic"]
