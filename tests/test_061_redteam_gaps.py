"""0.60 red-team gaps: wiped access records, rewritten canaries, unsigned lengths, squatted slots.

Each attack below worked before 0.60: deleting ``access/`` reset the exposure
budget, deleting or overwriting a canary registration stopped it counting, an
unsigned code-lengths file passed ``canary-check``, and a forged next-sequence
file blocked every later unseal. Access records and canary registrations are
now held (``tine hold release`` refuses them) and read as the union of files
and held copies; code lengths must be signed by a pinned scorer key.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from opentine._canary_check import sign_lengths
from opentine._holdout import sign
from opentine._holdout_access import ACCESS, exposure
from opentine._integrity_run import _sign
from opentine.repository._holds import HoldError, release
from tests.holdout_helpers import DATASET, EVAL, OPTIMIZER, SCORER, Hold, codes, lengths_file, tine
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.promote_helpers import AT, key

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")
CANARY = "tine-canary 4e1f0a9b7c2d3e5f6a8b"


@pytest.fixture
def hold(tmp_path: Path) -> Hold:
    return Hold(tmp_path)


def _canary(hold: Hold, capsys, seed: str = DATASET) -> dict:
    code, row = tine(capsys, "dataset", "canary-add", CANARY, "--entropy-bits", "128",
                     "--holdout", "h1", "--key", hold.keys[seed], "--repo",
                     hold.root.as_posix(), "--at", AT, "--json")  # fmt: skip
    assert code == 0, row
    return row["canary"]


def _check(hold: Hold, capsys, path: str, *extra: str) -> tuple[int, dict]:
    return tine(capsys, "dataset", "canary-check", path, "--repo", hold.root.as_posix(),
                "--json", *extra)  # fmt: skip


def test_wiping_the_access_records_does_not_reset_the_budget(hold: Hold, capsys) -> None:
    assert hold.seal(capsys, unseals=1, items=6)[0] == 0
    assert hold.unseal(capsys, "--items", "0")[0] == 0
    shutil.rmtree(hold.folder() / "access")
    state = exposure(hold.folder(), hold.root)
    assert (state["unseals"], state["revealed"], state["chain_ok"]) == (1, 1, True)
    code, row = hold.unseal(capsys, "--items", "1", out="again.jsonl")
    assert code == 1 and codes(row) == {"holdout.budget-exceeded"}


def test_a_held_access_record_is_never_released(hold: Hold, capsys) -> None:
    assert hold.seal(capsys)[0] == 0
    assert hold.unseal(capsys, "--items", "0")[0] == 0
    root = exposure(hold.folder(), hold.root)["root"]
    with pytest.raises(HoldError, match="never released"):
        release(hold.repo, f"holdout-access:{root}:000000")


def test_a_deleted_canary_registration_still_counts(hold: Hold, capsys) -> None:
    canary = _canary(hold, capsys)
    Path(canary["path"]).unlink()
    code, row = _check(hold, capsys, lengths_file(hold.base / "l.json",
                                                  {canary["canary_sha256"]: 3}))  # fmt: skip
    assert code == 1 and {f["code"] for f in row["findings"]} == {"dataset.canary-below-entropy"}
    with pytest.raises(HoldError, match="never released"):
        release(hold.repo, f"holdout-canary:{canary['canary_sha256']}")


def test_an_overwritten_canary_registration_is_refused_as_tampered(hold: Hold, capsys) -> None:
    canary = _canary(hold, capsys)
    path = Path(canary["path"])
    doc = json.loads(path.read_bytes())
    forged = _sign(key(OPTIMIZER), {**doc["claim"], "entropy_bits": 1}, doc["target_id"], AT)
    path.write_bytes(json.dumps(forged).encode("utf-8"))
    code, row = _check(hold, capsys, lengths_file(hold.base / "l.json",
                                                  {canary["canary_sha256"]: 3}))  # fmt: skip
    assert code != 0 and "canary.tampered" in row["error"]["message"], row


@pytest.mark.parametrize("how", ["unsigned", "optimizer", "dataset", "unbound", "other-run"])
def test_code_lengths_must_be_signed_by_a_pinned_scorer_for_the_run(hold, capsys, how) -> None:
    canary = _canary(hold, capsys)
    scores = {canary["canary_sha256"]: 3}  # far below the declared 128 bits
    path, extra = hold.base / "l.json", ()
    if how == "unsigned":
        path.write_bytes(json.dumps(scores).encode("utf-8"))
    elif how in ("optimizer", "dataset"):
        lengths_file(path, scores, seed=OPTIMIZER if how == "optimizer" else DATASET)
    elif how == "unbound":
        doc = sign_lengths(key(SCORER), "run-a", scores, None, AT)
        path.write_bytes(json.dumps(_sign(key(SCORER), doc["claim"], "run-b", AT)).encode())
    else:
        lengths_file(path, scores, run="run-a")
        extra = ("--run", "run-b")
    code, row = _check(hold, capsys, path.as_posix(), *extra)
    assert code != 0 and "canary.unsigned" in row["error"]["message"], row
    code, row = _check(hold, capsys, lengths_file(path, scores, run="run-b"), "--run", "run-b")
    assert code == 1 and row["run"] == "run-b" and not row["ok"]


def _forged(hold: Hold, seed: str, sequence: int, previous: str | None, run: str) -> bytes:
    root = exposure(hold.folder(), hold.root)["root"]
    record = {"schema": ACCESS, "holdout": "h1", "root": root, "sequence": sequence,
              "previous": previous, "run": run, "why": "x", "purpose": "eval", "items": [0],
              "over_budget": False}  # fmt: skip
    return json.dumps(sign(key(seed), record, f"sha256:{root}", AT)).encode("utf-8")


@pytest.mark.parametrize("squatter", ["garbage", "optimizer"])
def test_a_forged_next_record_does_not_block_unseal(hold: Hold, capsys, squatter) -> None:
    assert hold.seal(capsys, unseals=3, items=6)[0] == 0
    assert hold.unseal(capsys, "--items", "0")[0] == 0
    first = exposure(hold.folder(), hold.root)["records"][0]["sha256"]
    slot = hold.folder() / "access" / "000001.json"
    slot.write_bytes(b"{not json" if squatter == "garbage" else
                     _forged(hold, OPTIMIZER, 1, first, "squat"))  # fmt: skip
    assert hold.unseal(capsys, "--items", "1", out="b.jsonl")[0] == 0
    state = exposure(hold.folder(), hold.root)
    assert (state["unseals"], state["chain_ok"]) == (2, True)


def test_two_valid_records_for_one_sequence_fail_closed(hold: Hold, capsys) -> None:
    assert hold.seal(capsys, unseals=3, items=6)[0] == 0
    assert hold.unseal(capsys, "--items", "0")[0] == 0
    first = exposure(hold.folder(), hold.root)["records"][0]["sha256"]
    assert hold.unseal(capsys, "--items", "1", out="b.jsonl")[0] == 0
    (hold.folder() / "access" / "000001-twin.json").write_bytes(
        _forged(hold, EVAL, 1, first, "twin"))  # fmt: skip
    assert exposure(hold.folder(), hold.root)["chain_ok"] is False
