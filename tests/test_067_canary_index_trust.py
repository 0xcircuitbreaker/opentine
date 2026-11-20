"""Audit fs-1: the canary scan index is a cache an agent loop can write.

Deleting a row from ``hits`` (or planting an index that marks every object
scanned with no hits) must not hide a leak: rows are stamped with this user's
local secret over the object id, the canary set and the hits, and a row whose
stamp does not verify is read again. A linked index file is refused.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from opentine._canary_scan import INDEX
from opentine.repository import Repo
from tests.test_061_canary import CANARY, _register, _run, _scan, root  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


@pytest.fixture(autouse=True)
def _secret_home(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "cfg").as_posix())


def _leak(capsys, root: Path) -> None:  # noqa: F811
    _register(capsys, root, CANARY, 96)
    Repo.open(root).put_run(_run(f"answer {CANARY}"))
    code, row = _scan(capsys, root)
    assert code == 1 and row["counts"]["matches"] == 1


def test_deleting_hits_does_not_hide_a_leak(capsys, root: Path) -> None:  # noqa: F811
    _leak(capsys, root)
    with sqlite3.connect(root / INDEX) as db:
        db.execute("DELETE FROM hits")
    code, row = _scan(capsys, root)
    assert code == 1 and row["ok"] is False and row["counts"]["matches"] == 1


def test_a_planted_index_does_not_hide_a_leak(capsys, root: Path) -> None:  # noqa: F811
    _leak(capsys, root)
    with sqlite3.connect(root / INDEX) as db:
        db.execute("DELETE FROM hits")
        key = db.execute("SELECT canaries FROM scanned LIMIT 1").fetchone()[0]
        db.execute("UPDATE scanned SET canaries = ?", (key.split(":hits")[0],))
    code, row = _scan(capsys, root)
    assert code == 1 and row["counts"]["matches"] == 1


def test_a_repeat_scan_still_answers_from_the_index(capsys, root: Path) -> None:  # noqa: F811
    _leak(capsys, root)
    code, row = _scan(capsys, root)
    assert code == 1 and row["counts"]["read"] == 0 and row["counts"]["matches"] == 1


def test_a_linked_index_is_refused(capsys, root: Path, tmp_path: Path) -> None:  # noqa: F811
    _register(capsys, root, CANARY, 96)
    Repo.open(root).put_run(_run(f"answer {CANARY}"))
    other = tmp_path / "elsewhere.sqlite"
    other.write_bytes(b"")
    (root / INDEX).parent.mkdir(parents=True, exist_ok=True)
    try:
        (root / INDEX).symlink_to(other)
    except OSError:
        pytest.skip("symlinks unavailable")
    code, row = _scan(capsys, root)
    assert code == 1 and row["counts"]["matches"] == 1
    assert other.read_bytes() == b""
