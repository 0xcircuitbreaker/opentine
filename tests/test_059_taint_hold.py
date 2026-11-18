"""0.59: an integrity taint survives the deletion of its file.

Before 0.59 a taint lived only in ``.tine/integrity/taints/HEX.json``, so a
loop that can write the repository could delete it and promote the run. Now
the signed taint is also stored and held (``integrity-taint:RUN``); ``tine
hold release`` refuses that hold, and promote and lineage read it. The
protected list also needs a pinned policy role (0.59 key roles).
"""

# ruff: noqa: F811 -- fixtures imported from the 0.57/0.58/0.60 suites
from __future__ import annotations

from pathlib import Path

import pytest

from opentine import Run
from opentine._integrity_run import LIST, TAINTS, load_list, promote_refusals, taints
from opentine.repository import Repo, _holds
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_060_integrity import TAINTER, _cli, _keyfile, _store, _tool, room  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def _tainted(room: Path, tmp_path: Path, capsys) -> str:
    hack = Run(id="hack-hold")
    _tool(hack, "Bash", command="rm tests/test_a.py")
    bad = _store(room, hack)
    code, row = _cli(capsys, "integrity", "check", bad, "--repo", room.as_posix(), "--key",
                     _keyfile(tmp_path, TAINTER), "--json")  # fmt: skip
    assert code == 1 and row["taint"]["hold"]
    return bad


def test_deleting_the_taint_file_does_not_un_taint(room: Path, tmp_path, capsys):
    bad = _tainted(room, tmp_path, capsys)
    (room / LIST).unlink()  # no live check: only the taint can refuse
    (room / TAINTS / f"{bad.rsplit(':', 1)[-1]}.json").unlink()
    assert [r["code"] for r in promote_refusals(room, bad)] == ["promote.score-tainted"]
    assert taints(room, bad)[0]["codes"] == ["fail:protected-surface-modified"]


def test_the_taint_hold_cannot_be_released(room: Path, tmp_path, capsys):
    bad = _tainted(room, tmp_path, capsys)
    with pytest.raises(_holds.HoldError, match="never released"):
        _holds.release(Repo.open(room), "integrity-taint:" + bad)


def test_an_unreadable_holds_file_taints(room: Path, tmp_path, capsys):
    bad = _tainted(room, tmp_path, capsys)
    (room / TAINTS / f"{bad.rsplit(':', 1)[-1]}.json").unlink()
    _holds.holds_path(Repo.open(room)).write_bytes(b"not json")
    assert taints(room, bad)[0]["codes"] == ["holds-unreadable"]


def test_an_unsigned_policy_role_cannot_pin_the_protected_list(room: Path):
    assert load_list(room)[2] == []
    (room / ".tine" / "trust-bundle.note").unlink()  # only the unsigned file is left
    findings = load_list(room)[2]
    assert [f["code"] for f in findings] == ["fail:protected-list-unsigned"]
    assert "unpinned" in findings[0]["detail"]
