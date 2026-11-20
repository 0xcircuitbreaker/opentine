"""``opentine.trends/1``: capability trends over lineage generations, from an export (0.72).

:func:`compute` is a pure function of an *export* (built from signed records by
:mod:`opentine._trends_collect`): per variant the mean score and pass rate with
0.57 bootstrap intervals (``_eval_stats._bootstrap``, integer micro-units), the
cost per success, the 50%-success time horizon (:mod:`opentine._trend_math`)
with a percentile bootstrap interval, and a paired comparison with each parent
whose significant drop is a regression. Generations summarise their variants.

The resampling stream for a number is SplitMix64 seeded with
``"opentine.trends/1:<seed>:<variant>:<metric>"``, so a browser running
``opentine/data/trends/recompute.mjs`` on the export gets the same bytes.
"""

from __future__ import annotations

from decimal import Decimal
from fractions import Fraction
from typing import Any

from opentine import _trend_math as tm
from opentine._eval_stats import MICRO, _bootstrap, micro, text

CONVENTION = "opentine.trends/1"
METRICS = ("score", "pass_rate")
MIN_BINS = 2


def _rng(data: dict[str, Any], variant: str, metric: str) -> tm.SplitMix:
    return tm.SplitMix(f"{CONVENTION}:{data['seed']}:{variant}:{metric}")


def _columns(items: list[dict[str, Any]]) -> dict[str, list[int]]:
    return {"score": [micro(i["score"]) for i in items],
            "pass_rate": [MICRO * bool(i["passed"]) for i in items]}  # fmt: skip


def _level(data: dict, variant: str, metric: str, values: list[int], alpha: Fraction) -> dict:
    n = len(values)
    if not n:
        return {"mean": None, "ci": None}
    ci = _bootstrap(values, _rng(data, variant, metric), data["resamples"], alpha)["ci"]
    return {"mean": text(Fraction(sum(values), n * MICRO)), "ci": ci}


def bins(items: list[dict[str, Any]]) -> list[tuple[str, float]]:
    """Distinct task lengths (decimal minutes) with their log2, shortest first."""
    lengths = sorted({i["minutes"] for i in items if i.get("minutes") is not None},
                     key=lambda m: (Decimal(m), m))  # fmt: skip
    return [(m, tm.log(float(m)) * tm.INV_LN2) for m in lengths]


def horizon(items: list[dict[str, Any]], *, alpha: Fraction, resamples: int,
            rng: tm.SplitMix) -> dict[str, Any]:  # fmt: skip
    """The 50%-success length in minutes and its studentized bootstrap interval.

    Items are resampled with replacement; each resample's crossing is
    studentized by its own delta-method standard error, and the interval is
    ``x - t[high] * se, x - t[low] * se`` on the log2 scale, at the 0.57
    positions. A resample that does not fit counts as an infinite t on the
    side its pass rate points to; an infinite bound is ``null``.
    """
    timed = [i for i in items if i.get("minutes") is not None]
    grid = bins(timed)
    where = {m: k for k, (m, _) in enumerate(grid)}
    rows = [(where[i["minutes"]], bool(i["passed"])) for i in timed]
    out = {
        "n": len(rows),
        "lengths": len(grid),
        "minutes": None,
        "ci": None,
        "reason": None,
        "failed_resamples": 0,
    }
    if len(grid) < MIN_BINS:
        out["reason"] = "fewer-than-two-lengths"
        return out

    def solve(sample: list[tuple[int, bool]]) -> tuple[float, float] | None:
        tries, wins = [0] * len(grid), [0] * len(grid)
        for k, ok in sample:
            tries[k] += 1
            wins[k] += ok
        cells = [(grid[k][1], tries[k], wins[k]) for k in range(len(grid)) if tries[k]]
        return tm.x50(tm.fit(cells))

    point = solve(rows)
    if point is None or not point[1] > 0.0:
        out["reason"] = "no-fit"
        return out
    x, se = point
    out["minutes"] = _bound(x)
    edge = float("inf") if sum(ok for _, ok in rows) * 2 >= len(rows) else float("-inf")
    draws = []
    for _ in range(resamples):
        got = solve([rows[rng.randrange(len(rows))] for _ in rows])
        draws.append(edge if got is None or not got[1] > 0.0 else (got[0] - x) / got[1])
    draws.sort()
    low, high = tm.quantile_index(alpha, resamples)
    out["ci"] = [_bound(x - draws[high] * se), _bound(x - draws[low] * se)]
    out["failed_resamples"] = sum(1 for d in draws if d in (float("inf"), float("-inf")))
    return out


def _bound(x: float) -> str | None:
    if x in (float("inf"), float("-inf")):
        return None
    return tm.micro_text(tm.exp(x * tm.LN2_HI + x * tm.LN2_LO))


def _versus(data: dict, row: dict, parent: dict, alpha: Fraction) -> dict[str, Any]:
    mine = {i["item"]: i for i in row["items"]}
    theirs = {i["item"]: i for i in parent["items"]}
    shared = sorted(set(mine) & set(theirs))
    out: dict[str, Any] = {"parent": parent["variant"], "n": len(shared), "regressions": []}
    for metric in METRICS:
        a = _columns([theirs[k] for k in shared])[metric]
        b = _columns([mine[k] for k in shared])[metric]
        diffs = [y - x for x, y in zip(a, b, strict=True)]
        if not diffs:
            out[metric] = {"delta": None, "ci": None, "significant": False}
            continue
        stream = _rng(data, row["variant"], f"{metric}-vs:{parent['variant']}")
        test = _bootstrap(diffs, stream, data["resamples"], alpha)
        delta = Fraction(sum(diffs), len(diffs) * MICRO)
        out[metric] = {"delta": text(delta), "ci": test["ci"], "significant": test["significant"]}
        if test["significant"] and delta < 0:
            out["regressions"].append(metric)
    return out


def _cost(row: dict[str, Any], passes: int) -> str | None:
    cost = row.get("cost_micro_usd")
    if cost is None or not passes:
        return None
    return text(Fraction(cost, passes * MICRO))


def _variant(data: dict, row: dict, by_id: dict, alpha: Fraction) -> dict[str, Any]:
    out = {"variant": row["variant"], "generation": row["generation"],
           "parents": row["parents"], "flags": row["flags"], "n": len(row["items"])}  # fmt: skip
    cols = _columns(row["items"])
    for metric in METRICS:
        out[metric] = _level(data, row["variant"], metric, cols[metric], alpha)
    out["cost_per_success"] = _cost(row, sum(1 for i in row["items"] if i["passed"]))
    out["horizon"] = horizon(row["items"], alpha=alpha, resamples=data["resamples"],
                             rng=_rng(data, row["variant"], "horizon"))  # fmt: skip
    out["vs_parents"] = [_versus(data, row, by_id[p], alpha)
                         for p in row["parents"] if p in by_id and by_id[p]["items"]]  # fmt: skip
    return out


def _generations(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for row in rows:
        gen = out.setdefault(
            row["generation"],
            {
                "generation": row["generation"],
                "variants": 0,
                "flagged": 0,
                "regressions": 0,
                "best": None,
            },
        )
        gen["variants"] += 1
        gen["flagged"] += bool(row["flags"])
        gen["regressions"] += sum(bool(v["regressions"]) for v in row["vs_parents"])
        mean = row["score"]["mean"]
        best = gen["best"]
        if mean is not None and not row["flags"] and (
                best is None or Decimal(mean) > Decimal(best["score"])):  # fmt: skip
            gen["best"] = {"variant": row["variant"], "score": mean,
                           "horizon_minutes": row["horizon"]["minutes"]}  # fmt: skip
    return [out[g] for g in sorted(out)]


def compute(data: dict[str, Any]) -> dict[str, Any]:
    """Every trends number from *data* (an ``opentine.trends/1`` export)."""
    from opentine._eval_stats import check

    if data.get("convention") != CONVENTION:
        raise ValueError(f"not an {CONVENTION} export")
    check("paired-bootstrap", data["alpha"], data["seed"], data["resamples"])
    if data["seed"] >= 2**53:
        raise ValueError("--seed must be below 2^53 (a browser reads it exactly)")
    alpha = Fraction(Decimal(data["alpha"]))
    by_id = {row["variant"]: row for row in data["variants"]}
    rows = [_variant(data, row, by_id, alpha) for row in data["variants"]]
    regressions = [{"variant": r["variant"], "parent": v["parent"], "metrics": v["regressions"]}
                   for r in rows for v in r["vs_parents"] if v["regressions"]]  # fmt: skip
    flagged = sorted({f for r in rows for f in r["flags"]})
    return {"convention": CONVENTION, "alpha": data["alpha"], "seed": data["seed"],
            "resamples": data["resamples"], "variants": rows,
            "generations": _generations(rows), "regressions": regressions,
            "flags": flagged}  # fmt: skip


__all__ = ["CONVENTION", "METRICS", "bins", "compute", "horizon"]
