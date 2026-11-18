#!/usr/bin/env python3
"""Reproduce ``tine eval compare --ci`` from its export, standard library only (0.58).

    python scripts/eval_compare_reproduce.py EXPORT.json

prints the ``stats`` object ``tine eval compare --ci ... --json`` printed for
the same export (``--export FILE``), byte for byte as JSON with sorted keys.
It imports nothing from opentine: it is an independent statement of the
convention ``opentine.eval-compare/1`` (docs/EVALS-PROMOTION.md).

All arithmetic is in integer micro-units; the resampling is Python's
``random.Random`` seeded with the string
``"opentine.eval-compare/1:<seed>:<metric>"``.
"""

from __future__ import annotations

import json
import math
import random
import sys
from decimal import ROUND_HALF_EVEN, Decimal
from fractions import Fraction

CONVENTION = "opentine.eval-compare/1"
MICRO = 1_000_000


def six(value: Fraction) -> str:
    number = Decimal(value.numerator) / Decimal(value.denominator)
    out = f"{number.quantize(Decimal('0.000001'), rounding=ROUND_HALF_EVEN):f}"
    return "0.000000" if out == "-0.000000" else out


def units(score: str) -> int:
    return int((Decimal(score) * MICRO).to_integral_value())


def metric(a: list[int], b: list[int], name: str, data: dict) -> dict:
    n, resamples = len(a), data["resamples"]
    alpha = Fraction(Decimal(data["alpha"]))
    diffs = [y - x for x, y in zip(a, b)]
    delta = Fraction(sum(diffs), n * MICRO) if n else Fraction(0)
    out = {"a": six(Fraction(sum(a), n * MICRO)) if n else None,
           "b": six(Fraction(sum(b), n * MICRO)) if n else None, "delta": six(delta),
           "ci": None, "p_value": None, "significant": False}  # fmt: skip
    if n:
        rng = random.Random(f"{CONVENTION}:{data['seed']}:{name}")
        if data["method"] == "paired-bootstrap":
            sums = sorted(sum(diffs[rng.randrange(n)] for _ in range(n)) for _ in range(resamples))
            lo = Fraction(sums[math.floor(alpha / 2 * resamples)], n * MICRO)
            hi = Fraction(sums[math.ceil((1 - alpha / 2) * resamples) - 1], n * MICRO)
            out.update({"ci": [six(lo), six(hi)], "significant": lo > 0 or hi < 0})
        else:
            observed, hits = abs(sum(diffs)), 0
            for _ in range(resamples):
                hits += abs(sum(d if rng.getrandbits(1) else -d for d in diffs)) >= observed
            p = Fraction(hits + 1, resamples + 1)
            out.update({"p_value": six(p), "significant": p < alpha})
    out["regression"] = out["significant"] and delta < 0
    out["improvement"] = out["significant"] and delta > 0
    return out


def reproduce(data: dict) -> dict:
    if data.get("convention") != CONVENTION:
        raise SystemExit(f"not an {CONVENTION} export")
    rows = data["items"]
    columns = {
        "score": ([units(r["a"]) for r in rows], [units(r["b"]) for r in rows]),
        "pass_rate": ([MICRO * bool(r["a_passed"]) for r in rows],
                      [MICRO * bool(r["b_passed"]) for r in rows]),
    }  # fmt: skip
    metrics = {name: metric(*columns[name], name, data) for name in ("score", "pass_rate")}
    return {
        "convention": CONVENTION,
        "method": data["method"],
        "alpha": data["alpha"],
        "seed": data["seed"],
        "resamples": data["resamples"],
        "n": len(rows),
        "metrics": metrics,
        "regressions": [m for m in ("score", "pass_rate") if metrics[m]["regression"]],
    }


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as handle:
        data = json.load(handle)
    # Bytes, so the output is identical on every OS (text stdout would write CRLF on Windows).
    sys.stdout.buffer.write((json.dumps(reproduce(data), sort_keys=True) + "\n").encode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
