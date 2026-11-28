"""0.91: the reference loop runs under a stop policy and halts at a fleet stop.

Each step first gets a signed continue proof and checks it (check-before-act);
the stop is issued at a chosen step, so the halt is fixed by order, not time.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
if str(EXAMPLES) not in sys.path:
    sys.path.insert(0, str(EXAMPLES))

from reference_loop.loop import run_loop  # noqa: E402
from reference_loop.models import StubModel  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def test_a_fleet_stop_halts_the_reference_loop_before_its_next_step(tmp_path):
    from opentine import _stop_policy
    from opentine.repo import Repo

    report = run_loop(tmp_path / "w", steps=3, model=StubModel(hack_at=None, regress_at=None),
                      stop_at=2)  # fmt: skip
    rows = report["steps"]
    assert "variant" in rows[0] and rows[1] == {"step": 2, "stopped": "fleet-stop"}
    assert len(rows) == 2
    policy = _stop_policy.load(Repo.open(tmp_path / "w" / "repo"))
    assert policy["fleet"] == "reference" and policy["window_s"] == 300
