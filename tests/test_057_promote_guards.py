"""0.57: ``tine promote`` honours the key-role policy and a loop stop.

The promoting key may not also hold a scorer, dataset, verdict or approver
key (``promote.key-separation``), and a stopped loop's candidate cannot move
a label (``promote.loop-stopped``). Reverting a stopped loop's label stays
allowed. Clocks are injected; nothing sleeps.
"""

from __future__ import annotations

import json

import pytest

from opentine.coord import _loop_stop
from opentine.repository import Repo
from tests.promote_helpers import EVALER, PROMOTER, RUN_B, fingerprint, key
from tests.test_058_promote import Room, _codes, _good

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")

T0 = 1_800_000_000_000


@pytest.fixture
def room(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    return Room(tmp_path)


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "r")


def _roles(repo: Repo, **roles: list[str]) -> None:
    lines = ["version = 1", "[roles]"]
    lines += [f"{role} = {json.dumps(keys)}" for role, keys in roles.items()]
    (repo.path / "key-roles.toml").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))


def _at(repo: Repo) -> list[str]:
    return ["--repo", repo.path.parent.as_posix()]


def test_a_promoting_key_that_also_signs_verdicts_is_refused(room, repo, capsys):
    _roles(repo, optimizer=[fingerprint(PROMOTER)],
           verdict=[fingerprint(EVALER), fingerprint(PROMOTER)])  # fmt: skip
    code, row = room.promote(capsys, RUN_B, *_good(room, capsys), *_at(repo))
    assert code == 1 and "promote.key-separation" in _codes(row)
    assert not (room.state / "prod.json").exists()


def test_separated_keys_promote(room, repo, capsys):
    _roles(repo, optimizer=[fingerprint(PROMOTER)], verdict=[fingerprint(EVALER)])
    code, row = room.promote(capsys, RUN_B, *_good(room, capsys), *_at(repo))
    assert code == 0, row.get("refusals")


def test_a_stopped_loop_cannot_promote_but_a_running_one_can(room, repo, capsys):
    args = [*_good(room, capsys), *_at(repo)]
    _loop_stop.stop(repo, "opt", key("8d" * 32), reason="regression", now=T0)
    code, row = room.promote(capsys, RUN_B, *args, "--loop", "opt")
    assert code == 1 and _codes(row) == {"promote.loop-stopped"}
    assert "verified" in row["refusals"][0]["detail"]
    assert not (room.state / "prod.json").exists()
    code, row = room.promote(capsys, RUN_B, *args, "--loop", "other")
    assert code == 0, row.get("refusals")
