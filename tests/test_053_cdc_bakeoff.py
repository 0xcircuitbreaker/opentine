"""0.53: the CDC bake-off uses the stored gear table and its page is generated."""

from __future__ import annotations

import importlib.util
import json
import random
import sys
from pathlib import Path

from opentine.remote import _fastcdc

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "scripts" / "bench"


def _load(name: str):
    sys.path.insert(0, str(BENCH))
    try:
        spec = importlib.util.spec_from_file_location(f"bench_{name}", BENCH / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(BENCH))


def test_the_bakeoff_uses_the_stored_gear_table_pinned_by_digest():
    bakeoff = _load("cdc_bakeoff")
    assert bakeoff._GEAR is _fastcdc._GEAR
    rng = random.Random(49)  # the documented generation: one generator, 256 draws
    assert tuple(rng.getrandbits(64) for _ in range(256)) == _fastcdc._GEAR
    assert len(set(_fastcdc._GEAR)) == 256
    assert bakeoff.gear_digest() == bakeoff.GEAR_SHA256
    bakeoff.check_gear()
    # The 0.40 table (a fresh Random(40) per entry) is the bug this pin refuses.
    broken = [random.Random(40).getrandbits(64) for _ in range(256)]
    assert len(set(broken)) == 1 and bakeoff.gear_digest(broken) != bakeoff.GEAR_SHA256


def test_the_bakeoff_cuts_on_content():
    bakeoff = _load("cdc_bakeoff")
    data = random.Random(53).randbytes(256 * 1024)
    sizes = [len(c) for c in bakeoff.fastcdc(data, 8 * 1024)]
    assert sum(sizes) == len(data) and len(set(sizes)) > 4  # not fixed-size blocks
    edited = data[:100] + b"x" + data[100:]
    after = {bytes(c) for c in bakeoff.fastcdc(edited, 8 * 1024)}
    assert len({bytes(c) for c in bakeoff.fastcdc(data, 8 * 1024)} - after) <= 2


def test_the_published_page_is_the_render_of_the_committed_report():
    report = json.loads((ROOT / "docs/bench/0.53-cdc.json").read_text("utf-8"))
    page = (ROOT / "docs/bench/0.53-cdc.md").read_text("utf-8")
    assert page == _load("cdc_report").render(report)
    assert report["schema"] == "opentine-cdc-bakeoff/2"
    assert report["pinned"] == _load("cdc_bakeoff").PINNED
    assert report["gear_sha256"] == _load("cdc_bakeoff").GEAR_SHA256
    assert "produced in CI" in page and "CDC bake-off (pinned runner)" in page
    workflow = (ROOT / ".github/workflows/bench.yml").read_text("utf-8")
    assert "name: CDC bake-off (pinned runner)" in workflow
    assert "scripts/bench/cdc_bakeoff.py --out cdc/cdc.json" in workflow
