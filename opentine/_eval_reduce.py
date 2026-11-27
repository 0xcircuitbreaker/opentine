"""The planned analysis of two evals: epochs reduced, clusters pooled, power reported (0.86).

:func:`analyse` turns the verdicts of a baseline and a candidate eval into the
test an ``opentine.eval-plan/1`` names:

1. **Reduce epochs.** Per item, its epoch verdicts become one value: for
   ``metric = "score"`` the mean (``mean``), the best (``pass@k``) or the worst
   (``pass^k``) score; for ``pass_rate`` the fraction passed, any passed, or all
   passed. An item missing an epoch is not paired.
2. **Pool clusters.** With a cluster key, an item's paired difference joins its
   cluster and each cluster contributes its mean difference: the effective n is
   the number of clusters, not of items, so correlated families do not
   overstate significance.
3. **Test** at the corrected alpha with the plan's test and resample count,
   seeded from the revealed plan seed (``random.Random`` over
   ``"opentine.eval-plan/1:<seed>:<metric>"``). A bootstrap with fewer than
   ``2 / alpha`` resamples cannot resolve the corrected interval: it is
   ``resolved: false`` and fails (fail closed).
4. **Power.** The standard error of the mean unit difference, the minimum
   detectable effect at 80% power and the power at the plan's ``mde``
   (two-sided normal approximation). Reported and signed, never a gate.
"""

from __future__ import annotations

import math
import random
from decimal import Decimal
from fractions import Fraction
from statistics import NormalDist
from typing import Any

from opentine import _eval_stats as stats
from opentine._eval_coverage import base_id

MICRO = stats.MICRO


def _value(rows: list[dict[str, Any]], metric: str, reducer: str) -> Fraction:
    if metric == "score":
        values = [Fraction(Decimal(r["score"])) for r in rows]
    else:
        values = [Fraction(int(bool(r["passed"]))) for r in rows]
    if reducer == "pass@k":
        return max(values)
    if reducer == "pass^k":
        return min(values)
    return sum(values, Fraction(0)) / len(values)


def reduced(rows: list[dict[str, Any]], epochs: int, metric: str,
            reducer: str) -> dict[str, Fraction]:  # fmt: skip
    """``{item: value}`` for every item with all *epochs* verdicts."""
    by: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by.setdefault(base_id(row["item"], epochs), []).append(row)
    return {item: _value(group, metric, reducer)
            for item, group in by.items() if len(group) == epochs}  # fmt: skip


def units(a: dict[str, Fraction], b: dict[str, Fraction],
          clusters: dict[str, str] | None) -> dict[str, Fraction]:  # fmt: skip
    """Paired differences (candidate minus baseline) per unit: item, or cluster mean."""
    diffs = {item: b[item] - a[item] for item in sorted(set(a) & set(b))}
    if not clusters:
        return diffs
    pooled: dict[str, list[Fraction]] = {}
    for item, diff in diffs.items():
        pooled.setdefault(clusters.get(item, f"item:{item}"), []).append(diff)
    return {name: sum(v, Fraction(0)) / len(v) for name, v in sorted(pooled.items())}


def _power(diffs: list[Fraction], alpha: Fraction, mde: Fraction) -> dict[str, Any]:
    n = len(diffs)
    if n < 2:
        return {"se": None, "mde_80": None, "power_at_mde": None}
    mean = sum(diffs, Fraction(0)) / n
    var = float(sum((d - mean) ** 2 for d in diffs) / (n - 1))
    se = math.sqrt(var / n)
    z = NormalDist().inv_cdf(1 - float(alpha) / 2)
    if se == 0:
        return {"se": "0.000000", "mde_80": "0.000000", "power_at_mde": "1.000000"}
    detect = (z + NormalDist().inv_cdf(0.8)) * se
    power = NormalDist().cdf(float(mde) / se - z)
    return {"se": stats.text(Fraction(se)), "mde_80": stats.text(Fraction(detect)),
            "power_at_mde": stats.text(Fraction(power))}  # fmt: skip


def analyse(left: list[dict[str, Any]], right: list[dict[str, Any]], plan: dict[str, Any], *,
            seed: int, alpha: str, clusters: dict[str, str] | None) -> dict[str, Any]:  # fmt: skip
    """The planned test of *right* (candidate) over *left* (baseline) at *alpha*."""
    epochs, metric, reducer = plan["epochs"], plan["metric"], plan["reducer"]
    a = reduced(left, epochs, metric, reducer)
    b = reduced(right, epochs, metric, reducer)
    found = units(a, b, clusters if plan["cluster_key"] else None)
    diffs = [round(d * MICRO) for d in found.values()]
    level = Fraction(Decimal(alpha))
    n = len(diffs)
    delta = Fraction(sum(diffs), n * MICRO) if n else Fraction(0)
    row: dict[str, Any] = {"metric": metric, "reducer": reducer, "epochs": epochs,
                           "items": len(set(a) & set(b)), "effective_n": n,
                           "cluster_key": plan["cluster_key"], "alpha": alpha,
                           "test": plan["test"], "resamples": plan["resamples"],
                           "delta": stats.text(delta)}  # fmt: skip
    # A bootstrap interval at alpha needs alpha/2 * R >= 1 resamples beyond each bound.
    row["resolved"] = plan["test"] == "permutation" or level / 2 * plan["resamples"] >= 1
    if n and row["resolved"]:
        rng = random.Random(f"opentine.eval-plan/1:{seed}:{metric}")
        if plan["test"] == "paired-bootstrap":
            row.update(stats._bootstrap(diffs, rng, plan["resamples"], level))
            row["passed"] = Fraction(Decimal(row["ci"][0])) > 0
        else:
            row.update(stats._permutation(diffs, rng, plan["resamples"], level))
            row["passed"] = row["significant"] and delta > 0
    else:
        row.update({"ci": None, "p_value": None, "significant": False, "passed": False})
    row.update(_power(list(found.values()), level, Fraction(Decimal(plan["mde"]))))
    return row


def corrected_alpha(alpha: str, correction: str, m: int, rank: int) -> str:
    """Per-test alpha: Bonferroni ``alpha/m``; Holm step ``rank`` (1-based) ``alpha/(m-rank+1)``."""
    step = m if correction == "bonferroni" else max(1, m - rank + 1)
    value = Decimal(alpha) / step
    return f"{value.normalize():f}" if value >= Decimal("1e-12") else "0.000000000001"


__all__ = ["analyse", "corrected_alpha", "reduced", "units"]
