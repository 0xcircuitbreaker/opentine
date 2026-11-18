"""0.60: ``tine promote`` refuses a tainted score (``promote.score-tainted``).

A candidate whose run carries a signed ``opentine.integrity.taint`` is never
promoted, nor one that trips a ``fail:`` against the signed protected list at
promotion time. Clocks are injected; nothing sleeps.
"""

from __future__ import annotations

import pytest

from opentine._integrity_run import LIST, taint
from opentine.repository import Repo
from tests.promote_helpers import AT, RUN_B, key
from tests.test_058_promote import Room, _codes, _good

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


@pytest.fixture
def room(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    return Room(tmp_path)


def test_a_tainted_candidate_is_refused_and_a_clean_one_promotes(room, tmp_path, capsys):
    repo = Repo.init(tmp_path / "r")
    at = ["--repo", repo.path.parent.as_posix()]
    args = [*_good(room, capsys), *at]
    fails = [{"level": "fail", "code": "fail:protected-surface-modified"}]
    taint(repo.path.parent, key("4f" * 32), {"run": RUN_B, "findings": fails,
                                            "protected_sha256": None}, AT)  # fmt: skip
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 1 and _codes(row) == {"promote.score-tainted"}
    assert not (room.state / "prod.json").exists()
    (repo.path / "integrity" / "taints").joinpath(f"{'b' * 64}.json").unlink()
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 0, row.get("refusals")


def test_an_unsigned_protected_list_fails_closed(room, tmp_path, capsys):
    repo = Repo.init(tmp_path / "r")
    (repo.path.parent / LIST).write_bytes(
        b'version = 1\n[[surface]]\nname = "g"\nkind = "grader"\nglobs = ["g/**"]\n'
    )
    code, row = room.promote(capsys, RUN_B, *_good(room, capsys), "--repo",
                             repo.path.parent.as_posix())  # fmt: skip
    assert code == 1 and _codes(row) == {"promote.score-tainted"}
    assert "fail:protected-list-unsigned" in row["refusals"][0]["detail"]
