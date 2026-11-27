"""0.87: ``tine promote`` under ``profile = "rsi"`` refuses an edit outside a region.

The 0.86 rsi fixture promotes a planned candidate; here the same promotion is
refused (``promote.region-modified``) while a locked line differs from the signed
region pin, and goes through once only the region itself has changed.
"""

from __future__ import annotations

import pytest

from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.plan_helpers import run, write_plan
from tests.promote_helpers import RUN_A, RUN_B
from tests.regions_helpers import pin_regions
from tests.test_086_promote_plan import _codes, _plan_args
from tests.test_086_promotion_discipline_e2e import EPOCHS, rsi_room  # noqa: F401
from tests.test_087_regions import BASE

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def test_rsi_refuses_an_edit_outside_the_region_and_allows_one_inside(rsi_room, capsys):  # noqa: F811
    room = rsi_room
    algo = room.repo / "evolve" / "algo.py"
    algo.parent.mkdir()
    algo.write_bytes(BASE.encode())
    pin_regions(room.repo)
    plan, reveal = write_plan(room.base, room.rows)
    base = run(room.base / "base", room.rows, RUN_A, EPOCHS[0])
    cand = run(room.base / "cand", room.rows, RUN_B, EPOCHS[1], plan=plan)
    args = ["--baseline-evals", base.as_posix(), "--evals", cand.as_posix(),
            *_plan_args(plan, reveal)]  # fmt: skip
    algo.write_bytes(BASE.replace("xs[-3:]", "xs").encode())  # the score inflates
    code, row = room.promote(capsys, *args, profile="rsi")
    assert code == 1 and _codes(row) == {"promote.region-modified"}
    (room.repo / "evolve" / "planted.py").write_bytes(b"x = 1\n")
    algo.write_bytes(BASE.replace("x * 2", "x * 4").encode())
    code, row = room.promote(capsys, *args, profile="rsi")
    assert code == 1 and "fail:region-file-added" in row["refusals"][0]["detail"]
    (room.repo / "evolve" / "planted.py").unlink()
    code, row = room.promote(capsys, *args, profile="rsi")
    assert code == 0, row.get("refusals")
