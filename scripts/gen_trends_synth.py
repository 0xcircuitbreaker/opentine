#!/usr/bin/env python3
"""Write ``tests/data/trends_horizon_synth.json``: 100 planted time-horizon datasets (0.72).

Each dataset draws, for every task length on a fixed grid, ``PER_LENGTH`` task
outcomes from the known logistic ``p = 1 / (1 + exp(-SLOPE * (log2 m - log2 H)))``
with ``random.Random(seed)``, seeds 0..99. ``H`` (the planted 50%-success
horizon, in minutes) and the slope are stored with the outcomes, so the
acceptance test (tests/test_072_trends_horizon.py) checks the fit against them.

    python scripts/gen_trends_synth.py [OUT]
"""

from __future__ import annotations

import json
import math
import random
import sys
from pathlib import Path

HORIZON = "30"
SLOPE = -0.9
LENGTHS = ("1", "2", "4", "8", "15", "30", "60", "120", "240", "480", "960", "1920")
PER_LENGTH = 16
SEEDS = 100


def dataset(seed: int) -> str:
    """One dataset's outcomes as a bit string, lengths in grid order."""
    rng = random.Random(seed)
    bits = []
    for minutes in LENGTHS:
        x = math.log2(float(minutes)) - math.log2(float(HORIZON))
        p = 1.0 / (1.0 + math.exp(-SLOPE * x))
        bits += ["1" if rng.random() < p else "0" for _ in range(PER_LENGTH)]
    return "".join(bits)


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/data/trends_horizon_synth.json")
    body = {"horizon_minutes": HORIZON, "slope_per_log2": SLOPE, "lengths": list(LENGTHS),
            "per_length": PER_LENGTH, "outcomes": [dataset(s) for s in range(SEEDS)]}  # fmt: skip
    out.write_bytes((json.dumps(body, indent=1) + "\n").encode("utf-8"))


if __name__ == "__main__":
    main()
