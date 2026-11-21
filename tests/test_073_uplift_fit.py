"""0.73: the time-horizon fit recovers a planted horizon; refused fits are refused."""

from __future__ import annotations

import math
from pathlib import Path

from opentine import _uplift_fit, _uplift_synth
from opentine.kernel import canonical_json

DATA = Path(__file__).parent / "data" / "uplift_synthetic.json"


def test_committed_dataset_is_the_generator_output_for_seed_0() -> None:
    assert DATA.read_bytes() == canonical_json(_uplift_synth.generate(0)) + b"\n"


def test_planted_horizon_inside_the_95_ci_in_at_least_95_of_100_seeds() -> None:
    inside = 0
    for seed in range(100):
        data = _uplift_synth.generate(seed)
        fit = _uplift_fit.horizon(_uplift_synth.points(data), seed=seed, resamples=500)
        assert fit["status"] == "ok", (seed, fit)
        lo, hi = (float(v) for v in fit["ci"])
        inside += lo <= _uplift_synth.HORIZON <= hi
    assert inside >= 95, inside


def test_fit_on_the_committed_dataset_is_deterministic() -> None:
    import json

    points = _uplift_synth.points(json.loads(DATA.read_bytes()))
    first = _uplift_fit.horizon(points, seed=3, resamples=50)
    assert first == _uplift_fit.horizon(points, seed=3, resamples=50)
    assert first["bootstrap_used"] + first["bootstrap_failed"] == 50
    assert first["slope"].startswith("-")


def _pts(rows: list[tuple[int, bool]]) -> list[tuple[float, bool]]:
    return [(math.log2(m), ok) for m, ok in rows]


def test_small_n_no_variation_and_separation_are_refused() -> None:
    few = _pts([(1, True), (8, True), (64, False)])
    assert _uplift_fit.fit(few)["status"] == "insufficient-data"
    two = _pts([(1, True)] * 6 + [(64, False)] * 6)
    assert _uplift_fit.fit(two)["status"] == "insufficient-lengths"
    flat = _pts([(m, True) for m in (1, 2, 4, 8, 16)] * 3)
    assert _uplift_fit.fit(flat)["status"] == "no-variation"
    separated = _pts([(m, m < 8) for m in (1, 2, 4, 8, 16, 32)] * 3)
    refused = _uplift_fit.horizon(separated, seed=0, resamples=10)
    assert refused["status"] == "not-converged"
    assert refused["horizon_minutes"] is None and refused["ci"] is None
    rising = _pts([(m, m >= 8) for m in (1, 2, 4, 8, 16, 32)] * 2 + [(4, True), (16, False)])
    assert _uplift_fit.fit(rising)["status"] == "no-decline"
