"""The 0.72 time-horizon fit: planted-horizon recovery, determinism, browser parity."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

import pytest

from opentine import _trend_math as tm
from opentine._trends import compute, horizon
from opentine.kernel import canonical_json

ROOT = Path(__file__).resolve().parents[1]
SYNTH = json.loads((ROOT / "tests" / "data" / "trends_horizon_synth.json").read_bytes())
SCRIPT = ROOT / "opentine" / "data" / "trends" / "recompute.mjs"
ALPHA = Fraction(1, 20)


def items(bits: str) -> list[dict]:
    per = SYNTH["per_length"]
    return [{"item": f"t{k:02d}-{j:02d}", "score": "1" if bits[k * per + j] == "1" else "0",
             "passed": bits[k * per + j] == "1", "minutes": m}
            for k, m in enumerate(SYNTH["lengths"]) for j in range(per)]  # fmt: skip


def covers(row: dict, planted: Decimal) -> bool:
    low, high = row["ci"]
    return (low is None or Decimal(low) <= planted) and (high is None or Decimal(high) >= planted)


def test_planted_horizon_inside_the_95_interval_in_95_of_100_seeds() -> None:
    planted = Decimal(SYNTH["horizon_minutes"])
    assert len(SYNTH["outcomes"]) == 100
    hits = 0
    for seed, bits in enumerate(SYNTH["outcomes"]):
        row = horizon(items(bits), alpha=ALPHA, resamples=1000, rng=tm.SplitMix(f"synth:{seed}"))
        assert row["reason"] is None and row["n"] == len(bits)
        hits += covers(row, planted)
    assert hits >= 95


def test_committed_dataset_is_what_the_generator_writes(tmp_path) -> None:
    out = tmp_path / "synth.json"
    subprocess.run([sys.executable, (ROOT / "scripts" / "gen_trends_synth.py").as_posix(),
                    out.as_posix()], check=True, timeout=120)  # fmt: skip
    assert out.read_bytes() == (ROOT / "tests" / "data" / "trends_horizon_synth.json").read_bytes()


def test_point_estimate_tracks_the_planted_horizon() -> None:
    planted = float(SYNTH["horizon_minutes"])
    rows = [horizon(items(b), alpha=ALPHA, resamples=100, rng=tm.SplitMix("p"))
            for b in SYNTH["outcomes"][:20]]  # fmt: skip
    found = sorted(float(r["minutes"]) for r in rows)
    assert found[0] < planted < found[-1]
    assert planted / 2 < found[len(found) // 2] < planted * 2


def test_too_few_lengths_and_no_fit_are_named() -> None:
    one = [{"item": f"i{j}", "score": "1", "passed": j % 2 == 0, "minutes": "5"} for j in range(9)]
    assert horizon(one, alpha=ALPHA, resamples=100, rng=tm.SplitMix("x"))["reason"] == (
        "fewer-than-two-lengths"
    )
    rising = [{"item": f"i{j}", "score": "1", "passed": (j % 4) < (1 + j // 10 % 3),
               "minutes": str(1 + j // 10)} for j in range(30)]  # fmt: skip
    row = horizon(rising, alpha=ALPHA, resamples=100, rng=tm.SplitMix("x"))
    assert row["reason"] == "no-fit" and row["minutes"] is None  # success rises with length


@pytest.mark.parametrize("x", [0.0, 1e-300, 0.5, 1.0, 2.0, 30.0, 1e10, 7.25e-5])
def test_log_and_exp_agree_with_the_platform_closely(x) -> None:
    import math

    if x < 700:
        assert tm.exp(x) == pytest.approx(math.exp(x), rel=1e-14)
        assert tm.exp(-x) == pytest.approx(math.exp(-x), rel=1e-14)
    if x > 0:
        assert tm.log(x) == pytest.approx(math.log(x), rel=1e-14, abs=1e-15)
    assert tm.sqrt(x) == pytest.approx(math.sqrt(x), rel=1e-15)


def test_quantile_positions_match_0_57() -> None:
    import math

    for alpha in (Fraction(1, 20), Fraction(1, 10), Fraction(3, 1000)):
        for r in (100, 199, 2000):
            assert tm.quantile_index(alpha, r) == (
                math.floor(alpha / 2 * r),
                math.ceil((1 - alpha / 2) * r) - 1,
            )


def _export() -> dict:
    variants = []
    for n, bits in enumerate(SYNTH["outcomes"][:3]):
        variants.append({"variant": f"sha256:{n:064x}", "generation": n,
                         "parents": [f"sha256:{n - 1:064x}"] if n else [], "loop": None,
                         "flags": ["lineage.score-tainted"] if n == 2 else [],
                         "items": items(bits), "cost_micro_usd": 1234567 * (n + 1)})  # fmt: skip
    return {"convention": "opentine.trends/1", "alpha": "0.05", "seed": 3, "resamples": 120,
            "variants": variants}  # fmt: skip


def test_compute_is_deterministic_and_costs_are_exact() -> None:
    data = _export()
    one, two = compute(data), compute(json.loads(json.dumps(data)))
    assert canonical_json(one) == canonical_json(two)
    passes = sum(i["passed"] for i in data["variants"][0]["items"])
    expected = (Fraction(1234567, passes * 1_000_000)).limit_denominator(10**12)
    assert abs(Fraction(Decimal(one["variants"][0]["cost_per_success"])) - expected) <= Fraction(
        1, 2_000_000
    )
    assert one["generations"][2]["best"] is None and one["flags"] == ["lineage.score-tainted"]


def test_browser_recompute_matches_python(tmp_path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    data = _export()
    path = tmp_path / "export.json"
    path.write_bytes(canonical_json(data))
    done = subprocess.run([node, SCRIPT.as_posix(), path.as_posix()], capture_output=True,
                          timeout=300, check=True)  # fmt: skip
    assert done.stdout == canonical_json(compute(data)) + b"\n"
