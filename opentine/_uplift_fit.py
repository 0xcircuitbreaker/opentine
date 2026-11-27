"""Time-horizon fit for ``tine uplift`` (0.73): pure-stdlib logistic regression.

Success is modelled as ``p = 1 / (1 + exp(-(a + b * log2(minutes))))`` where
*minutes* is the task length named by the suite. The **50%-success time
horizon** is the length where ``p = 0.5``: ``2 ** (-a / b)`` minutes. The fit
is maximum likelihood by Newton's method on points grouped by length, so a fit
costs O(distinct lengths) per iteration.

A fit is **refused** (``status`` is not ``ok``, horizon null) when it has fewer
than :data:`MIN_POINTS` points or :data:`MIN_LENGTHS` distinct lengths, when
every attempt succeeded or every one failed, when Newton's method does not
converge (perfect separation drives the slope to infinity), or when the slope
is not negative (success does not fall with length, so there is no horizon).

The interval is a seeded percentile bootstrap: *resamples* resamples of the
points with replacement drawn by ``random.Random(seed)``; resamples whose fit
is refused are counted in ``failed`` and left out. Numbers are reported as
fixed 6-decimal strings, so the same input gives the same bytes.
"""

from __future__ import annotations

import math
import random
from typing import Any

MIN_POINTS = 10
MIN_LENGTHS = 3
MAX_ITER = 100
TOL = 1e-10
_LIMIT = 1e6


def fmt(value: float) -> str:
    """A fixed 6-decimal string (the reporting form of every number)."""
    return f"{value:.6f}"


def _group(points: list[tuple[float, bool]]) -> list[tuple[float, int, int]]:
    """``[(x, successes, trials)]`` sorted by x."""
    table: dict[float, list[int]] = {}
    for x, ok in points:
        cell = table.setdefault(x, [0, 0])
        cell[0] += 1 if ok else 0
        cell[1] += 1
    return [(x, s, n) for x, (s, n) in sorted(table.items())]


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def _refusal(points: list[tuple[float, bool]], groups: list) -> str | None:
    if len(points) < MIN_POINTS:
        return "insufficient-data"
    if len(groups) < MIN_LENGTHS:
        return "insufficient-lengths"
    wins = sum(s for _x, s, _n in groups)
    if wins == 0 or wins == len(points):
        return "no-variation"
    return None


def fit(points: list[tuple[float, bool]]) -> dict[str, Any]:
    """Fit ``(log2 minutes, success)`` points: ``{status, a, b, horizon, iterations}``."""
    groups = _group(points)
    refused = _refusal(points, groups)
    if refused:
        return {"status": refused, "a": None, "b": None, "horizon": None, "iterations": 0}
    a = b = 0.0
    for step in range(1, MAX_ITER + 1):
        g0 = g1 = h00 = h01 = h11 = 0.0
        for x, s, n in groups:
            p = _sigmoid(a + b * x)
            w = n * p * (1.0 - p)
            g0 += s - n * p
            g1 += (s - n * p) * x
            h00 += w
            h01 += w * x
            h11 += w * x * x
        det = h00 * h11 - h01 * h01
        if not det > 0.0:
            break
        da = (h11 * g0 - h01 * g1) / det
        db = (h00 * g1 - h01 * g0) / det
        a, b = a + da, b + db
        if abs(a) > _LIMIT or abs(b) > _LIMIT:
            break
        if abs(da) < TOL and abs(db) < TOL:
            if not b < 0.0:
                return {"status": "no-decline", "a": a, "b": b, "horizon": None,
                        "iterations": step}  # fmt: skip
            log_h = -a / b
            if abs(log_h) > 60:
                break
            return {"status": "ok", "a": a, "b": b, "horizon": 2.0**log_h, "iterations": step}
    return {"status": "not-converged", "a": None, "b": None, "horizon": None,
            "iterations": MAX_ITER}  # fmt: skip


def _pick(rng: random.Random, pool: list) -> list:
    n = len(pool)
    return [pool[int(rng.random() * n)] for _ in range(n)]


def _sample(rng: random.Random, points: list, groups: list[list] | None) -> list:
    """Flat resampling, or (0.86) two-stage: clusters with replacement, then points
    with replacement inside each drawn cluster."""
    if groups is None:
        return _pick(rng, points)
    return [p for group in _pick(rng, groups) for p in _pick(rng, group)]


def bootstrap(points: list[tuple[float, bool]], *, seed: int, resamples: int,
              alpha: float = 0.05,
              clusters: list[str] | None = None) -> dict[str, Any]:  # fmt: skip
    """Percentile interval of the horizon: ``{ci: [lo, hi] | None, used, failed}``.

    *clusters* (one label per point) selects the hierarchical bootstrap."""
    rng = random.Random(seed)
    groups = None
    if clusters is not None:
        table: dict[str, list] = {}
        for label, point in zip(clusters, points, strict=True):
            table.setdefault(label, []).append(point)
        groups = [table[k] for k in sorted(table)]
    horizons: list[float] = []
    failed = 0
    for _ in range(resamples):
        sample = _sample(rng, points, groups)
        result = fit(sample)
        if result["status"] == "ok":
            horizons.append(result["horizon"])
        else:
            failed += 1
    if not horizons:
        return {"ci": None, "used": 0, "failed": failed}
    horizons.sort()
    m = len(horizons)
    lo = horizons[max(0, math.floor(alpha / 2 * m))]
    hi = horizons[min(m - 1, math.ceil((1 - alpha / 2) * m) - 1)]
    return {"ci": [lo, hi], "used": m, "failed": failed}


def horizon(points: list[tuple[float, bool]], *, seed: int, resamples: int,
            alpha: float = 0.05, clusters: list[str] | None = None) -> dict[str, Any]:  # fmt: skip
    """The reported fit: point estimate, seeded bootstrap interval, all as strings."""
    point = fit(points)
    out: dict[str, Any] = {
        "status": point["status"], "n": len(points),
        "successes": sum(1 for _x, ok in points if ok),
        "lengths": len({x for x, _ok in points}),
        "intercept": None, "slope": None, "horizon_minutes": None, "ci": None,
        "iterations": point["iterations"], "bootstrap_used": 0, "bootstrap_failed": 0,
    }  # fmt: skip
    if point["status"] != "ok":
        return out
    out.update(intercept=fmt(point["a"]), slope=fmt(point["b"]),
               horizon_minutes=fmt(point["horizon"]))  # fmt: skip
    boot = bootstrap(points, seed=seed, resamples=resamples, alpha=alpha, clusters=clusters)
    out.update(bootstrap_used=boot["used"], bootstrap_failed=boot["failed"],
               ci=[fmt(v) for v in boot["ci"]] if boot["ci"] else None)  # fmt: skip
    return out


__all__ = ["MIN_LENGTHS", "MIN_POINTS", "bootstrap", "fit", "fmt", "horizon"]
