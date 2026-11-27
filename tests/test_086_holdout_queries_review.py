"""0.86 review: holes in holdout query accounting, each pinned by a test.

Bytes I/O, no sleeps, everything under the test's own ``tmp_path``.
"""

from __future__ import annotations

import pytest

from opentine._holdout_query import counts
from tests.holdout_helpers import EVAL, tine
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_086_holdout_queries import _eval, hold  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def test_spreading_queries_over_lineage_names_still_crosses_the_budget(hold, capsys) -> None:  # noqa: F811
    named = ("--holdout", hold.folder().as_posix())
    rows = [_eval(hold, capsys, n, *named, lineage=f"gen-{n}")["holdout_queries"][0]
            for n in range(3)]  # fmt: skip
    assert [r["count"] for r in rows] == [1, 1, 1]
    assert [r["over_budget"] for r in rows] == [False, False, True]
    state = counts(hold.folder(), hold.root)
    assert state["total"] == 3 and "*" in state["over_budget"]


def test_a_lineage_name_outside_the_pattern_is_refused(hold, capsys) -> None:  # noqa: F811
    for bad in ("*", "x" * 200, "../up"):
        argv = ["eval", "run", (hold.base / "out" / "released.jsonl").as_posix(), "--outputs",
                (hold.base / "outs.jsonl").as_posix(), "--scorer", "exact", "--key",
                hold.keys[EVAL], "--out", (hold.base / "evals" / "bad").as_posix(), "--repo",
                hold.root.as_posix(), "--json", "--lineage", bad]  # fmt: skip
        assert tine(capsys, *argv)[0] != 0
