"""Audit: ``merge-history apply`` never moves a promotion label.

A loop can hand-write ``.tine/promotion/prod.json`` in its own clone (no signed
decision, no VSA, no oversight, holdout, monitor or guards) and export it as
``--theirs-state``. The merge must refuse rather than land that label: labels
move only through ``tine promote``, which runs every gate.
"""

from __future__ import annotations

from tests.query_helpers import tine
from tests.test_069_history_merge_cli import AT, _other_side, _snap, _write, room  # noqa: F401


def test_a_hand_written_label_state_is_not_landed_by_merge(room, capsys) -> None:  # noqa: F811
    base = _snap(capsys, room)
    theirs, state, lineage = _other_side(room, base)
    files = [_write(room, "base.json", base), _write(room, "theirs.json", theirs)]
    code, _ = tine(capsys, "merge-history", "apply", "--repo", (room["base"] / "r").as_posix(),
                   "--base", files[0], "--theirs", files[1],
                   "--key", (room["base"] / "k.key").as_posix(), "--subject",
                   room["runs"]["b"], "--at", AT, "--theirs-state", state.as_posix(),
                   "--theirs-lineage", lineage.as_posix())  # fmt: skip
    assert code == 1
    after = _snap(capsys, room)
    assert after["labels"] == base["labels"] and after["lineage"] == base["lineage"]
    assert after["holds"] == base["holds"]
