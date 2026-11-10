"""0.50: the criterion-6 bench gate (``scripts/bench/gate.py``) is relative and bytes-only."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _gate():
    spec = importlib.util.spec_from_file_location("bench_gate", ROOT / "scripts/bench/gate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _report(version: str, sizes: dict[str, int], speed: float = 1.0) -> dict:
    corpus = {"seed": 37, "runs": 40, "steps": 24, "objects": 1, "logical_bytes": 1000}
    results = {name: {"bytes": size, "mb_per_s": speed} for name, size in sizes.items()}
    return {"opentine": version, "corpus": corpus, "results": results}


SIZES = {"gc": 1000, "gc_v3": 500, "wire": 2000, "bundle": 2100, "zstd19_per_object": 900}


def test_within_five_percent_passes_and_speed_is_only_reported():
    gate = _gate()
    current = _report("0.50.0", {**SIZES, "gc": 1050}, speed=0.5)
    rows, ok = gate.evaluate(_report("0.40.0", SIZES), current, 0.05)
    assert ok
    assert {row["form"]: row["speed_vs_base"] for row in rows}["gc"] == 0.5


def test_a_gated_form_over_five_percent_fails_but_a_reference_row_does_not():
    gate = _gate()
    rows, ok = gate.evaluate(
        _report("0.40.0", SIZES), _report("0.50.0", {**SIZES, "wire": 2101}), 0.05
    )
    assert not ok and [r["form"] for r in rows if not r["pass"]] == ["wire"]
    bigger = {**SIZES, "zstd19_per_object": 5000}
    assert gate.evaluate(_report("0.40.0", SIZES), _report("0.50.0", bigger), 0.05)[1]


def test_a_missing_form_fails(tmp_path):
    gate = _gate()
    current = {k: v for k, v in SIZES.items() if k != "bundle"}
    assert not gate.evaluate(_report("0.40.0", SIZES), _report("0.50.0", current), 0.05)[1]
    base, now = tmp_path / "base.json", tmp_path / "now.json"
    base.write_text(json.dumps(_report("0.40.0", SIZES)))
    now.write_text(json.dumps(_report("0.50.0", SIZES)))
    assert gate.main(["--base", str(base), "--current", str(now)]) == 0
    other = _report("0.50.0", SIZES)
    other["corpus"]["runs"] = 10
    now.write_text(json.dumps(other))
    assert gate.main(["--base", str(base), "--current", str(now)]) == 2
