"""0.60: promote refuses an exposed holdout (named or kept in the repo) and a failed canary."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentine._promote_holdout import sealed_folders
from tests.holdout_helpers import DATASET, Hold, lengths_file, tine
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.promote_helpers import AT, RUN_B
from tests.test_058_promote import Room, _codes, _good

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")
CANARY = "c4a7f19e0b2d4e6f8a1c3e5b7d9f0a2c"


@pytest.fixture
def hold(tmp_path: Path, capsys) -> Hold:
    made = Hold(tmp_path)
    assert made.seal(capsys, unseals=1, items=6)[0] == 0
    return made


def _promote(hold: Hold, tmp_path: Path, capsys, name: str, *extra: str) -> tuple[int, dict]:
    (tmp_path / name).mkdir()
    room = Room(tmp_path / name)
    return room.promote(capsys, RUN_B, *_good(room, capsys), "--repo", hold.root.as_posix(),
                        *extra)  # fmt: skip


def test_a_repo_holdout_is_checked_without_the_flag(hold, tmp_path, capsys):
    assert sealed_folders([], hold.root) == [hold.folder()]
    assert sealed_folders([hold.folder()], hold.root) == [hold.folder()]
    assert hold.unseal(capsys)[0] == 0
    assert _promote(hold, tmp_path, capsys, "within")[0] == 0
    assert hold.unseal(capsys, "--exceed-budget", out="again.jsonl")[0] == 0
    code, row = _promote(hold, tmp_path, capsys, "over")
    assert code == 1 and _codes(row) == {"promote.holdout-exposed"}


def _lengths(hold: Hold, capsys, bits: float | None) -> str:
    code, row = tine(capsys, "dataset", "canary-add", CANARY, "--entropy-bits", "128",
                     "--holdout", "h1", "--key", hold.keys[DATASET], "--repo",
                     hold.root.as_posix(), "--at", AT, "--json")  # fmt: skip
    assert code == 0 and row["canary"]["counted"], row
    scored = {} if bits is None else {row["canary"]["canary_sha256"]: bits}
    return lengths_file(hold.base / "lengths.json", scored)


@pytest.mark.parametrize(("bits", "refused"), [(200.0, False), (12.5, True), (None, True)])
def test_a_failed_canary_check_refuses_promotion(hold, tmp_path, capsys, bits, refused):
    lengths = _lengths(hold, capsys, bits)
    code, row = _promote(hold, tmp_path, capsys, "p", "--canary-lengths", lengths)
    if refused:
        assert code == 1 and _codes(row) == {"promote.canary-failed"}, row
    else:
        assert code == 0, row.get("refusals")


def test_an_unreadable_lengths_file_refuses_promotion(hold, tmp_path, capsys):
    bad = hold.base / "bad.json"
    bad.write_bytes(b'{"x": NaN')
    code, row = _promote(hold, tmp_path, capsys, "p", "--canary-lengths", bad.as_posix())
    assert code == 1 and _codes(row) == {"promote.canary-failed"}
