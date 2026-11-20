"""Audit (statistics): the canary and the gate compare like with like."""

from __future__ import annotations

import pytest

from tests.promote_helpers import RUN_B
from tests.test_058_promote import _codes, _good, room  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def _promoted(room, capsys):  # noqa: F811
    code, row = room.promote(capsys, RUN_B, *_good(room, capsys), out="one")
    assert code == 0, row.get("refusals")
    return room.base / "base"


def _canary(room, capsys, canary, base):  # noqa: F811
    return room.promote(capsys, RUN_B, "--canary", canary.as_posix(), "--baseline-evals",
                        base.as_posix(), out="c")  # fmt: skip


def test_a_tiny_canary_is_refused_not_passed(room, capsys):  # noqa: F811
    base = _promoted(room, capsys)
    tiny = room.evals("tiny", RUN_B, lambda i: True, keep=lambda i: i < 2)
    code, row = _canary(room, capsys, tiny, base)
    assert code == 1 and row["action"] == "refused"
    assert {"promote.item-mismatch", "promote.n-below-minimum"} <= _codes(row)


def test_a_canary_on_another_dataset_is_refused(room, capsys):  # noqa: F811
    base = _promoted(room, capsys)
    other = room.evals("other", RUN_B, lambda i: True, dataset="else")
    code, row = _canary(room, capsys, other, base)
    assert code == 1 and "promote.dataset-mismatch" in _codes(row)


def test_a_one_item_canary_cannot_revert_an_honest_promotion(room, capsys):  # noqa: F811
    base = _promoted(room, capsys)
    one = room.evals("one-bad", RUN_B, lambda i: False, keep=lambda i: i == 0)
    code, row = _canary(room, capsys, one, base)
    assert code == 1 and row["action"] == "refused"
    assert "promote.n-below-minimum" in _codes(row)


def test_a_candidate_scored_under_a_lower_threshold_is_refused(room, capsys):  # noqa: F811
    args = _good(room, capsys)
    lenient = room.evals("lenient", RUN_B, lambda i: i % 10 != 0, threshold=0.0)
    args[args.index("--evals") + 1] = lenient.as_posix()
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 1 and "promote.scorer-mismatch" in _codes(row)


def test_a_holdout_scored_under_a_lower_threshold_is_refused(room, capsys):  # noqa: F811
    args = _good(room, capsys)
    lenient = room.evals("hlen", RUN_B, lambda i: i % 10 != 0, dataset="hold", threshold=0.0)
    args[args.index("--holdout") + 2] = lenient.as_posix()
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 1 and "promote.scorer-mismatch" in _codes(row)
