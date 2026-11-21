"""Synthetic uplift data from a known logistic (0.73), for checking the horizon fit.

Task lengths run log-uniformly from 1 minute to 16 hours; each task is tried
*attempts* times and succeeds with ``p = 1 / (1 + exp(-slope * (log2(m) -
log2(horizon))))``, so the planted 50%-success horizon is *horizon* minutes.
Draws come from ``random.Random(seed)`` and nothing else, so a seed always
gives the same dataset. ``scripts/gen_uplift_synthetic.py`` writes the
committed copy (seed 0) to ``tests/data/uplift_synthetic.json``.
"""

from __future__ import annotations

import math
import random
from typing import Any

HORIZON = 60
SLOPE = -0.8
TASKS = 24
ATTEMPTS = 8
FORMAT = "opentine-uplift-synthetic/1"


def lengths(tasks: int = TASKS) -> list[int]:
    """Whole-minute task lengths, log-uniform over 1..960 minutes."""
    return [max(1, round(2 ** (i * math.log2(960) / (tasks - 1)))) for i in range(tasks)]


def generate(seed: int, *, horizon: int = HORIZON, slope: float = SLOPE,
             tasks: int = TASKS, attempts: int = ATTEMPTS) -> dict[str, Any]:  # fmt: skip
    """``{format, seed, horizon, slope, tasks: [{id, minutes}], attempts: [[id, ok]]}``."""
    rng = random.Random(seed)
    table = [{"id": f"t{i:02d}", "minutes": m} for i, m in enumerate(lengths(tasks))]
    rows = []
    for task in table:
        z = slope * (math.log2(task["minutes"]) - math.log2(horizon))
        p = 1.0 / (1.0 + math.exp(-z))
        rows += [[task["id"], rng.random() < p] for _ in range(attempts)]
    return {"format": FORMAT, "seed": seed, "horizon": horizon, "slope": f"{slope:.6f}",
            "tasks": table, "attempts": rows}  # fmt: skip


def points(data: dict[str, Any]) -> list[tuple[float, bool]]:
    """The ``(log2 minutes, success)`` points of a generated dataset."""
    minutes = {t["id"]: t["minutes"] for t in data["tasks"]}
    return [(math.log2(minutes[tid]), bool(ok)) for tid, ok in data["attempts"]]


__all__ = ["ATTEMPTS", "FORMAT", "HORIZON", "SLOPE", "TASKS", "generate", "lengths", "points"]
