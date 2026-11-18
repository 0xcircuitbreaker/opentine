"""0.61: sealed holdouts, signed access records, exposure budgets and rotation.

Every hashed file is bytes; nothing sleeps; each repository lives under the
test's own ``tmp_path``; the trust config is per test (key_roles_helpers).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine._holdout import HoldoutError, load, merkle_root, open_items
from opentine._holdout_access import exposure, promote_refusals
from tests.holdout_helpers import DATASET, ITEMS, OPTIMIZER, Hold, codes, tine
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


@pytest.fixture
def hold(tmp_path: Path) -> Hold:
    return Hold(tmp_path)


def _released(hold: Hold, out: str = "released.jsonl") -> list[dict]:
    lines = (hold.base / "out" / out).read_bytes().decode("utf-8").splitlines()
    return [json.loads(line) for line in lines]


def test_seal_commits_to_the_items_and_keeps_none_in_clear(hold: Hold, capsys) -> None:
    code, row = hold.seal(capsys)
    assert code == 0 and row["items"] == 6 and row["generation"] == 1
    assert row["previous"] is None and row["budget"] == {"max_unseals": 2, "max_items": 4}
    found = load(hold.folder())
    assert found["claim"]["root"] == row["root"] == merkle_root(found["leaves"]).hex()
    for path in hold.folder().rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert not any(item["expected"].encode() in data for item in ITEMS), path
            assert b"lighthouse" not in data, path


def test_seal_needs_a_pinned_dataset_key_and_a_key_outside_the_folder(hold, capsys) -> None:
    code, row = hold.seal(capsys, seed=OPTIMIZER)
    assert code == 1 and codes(row) == {"holdout.role"}
    hold.seal_key = (hold.folder() / "seal.key").as_posix()
    code, row = hold.seal(capsys)
    assert code == 1 and codes(row) == {"holdout.seal-key"}


def test_unseal_needs_an_eval_role_key(hold: Hold, capsys) -> None:
    assert hold.seal(capsys)[0] == 0
    for seed in (DATASET, OPTIMIZER):
        code, row = hold.unseal(capsys, seed=seed)
        assert code == 1 and codes(row) == {"holdout.role"}
    assert not (hold.folder() / "access").exists()
    (hold.repo.path / "trust-bundle.note").unlink()  # the roles are now only the file
    code, row = hold.unseal(capsys)
    assert code == 1 and "owner-pinned" in row["refusals"][0]["detail"]


def test_unseal_records_who_which_run_and_why_before_release(hold, capsys) -> None:
    assert hold.seal(capsys)[0] == 0
    code, row = hold.unseal(capsys, "--items", "0,2", run="run:sha256:" + "a" * 64)
    assert code == 0 and row["items"] == 2 and row["over_budget"] is False
    assert [item["id"] for item in _released(hold)] == ["h-00", "h-02"]
    doc = json.loads(Path(row["access"]).read_bytes())
    claim = doc["claim"]
    assert claim["schema"] == "opentine.holdout.access/1" and claim["why"] == "scoring"
    assert (claim["run"], claim["items"], claim["sequence"]) == ("run:sha256:" + "a" * 64,
                                                                  [0, 2], 0)  # fmt: skip
    assert doc["signer"] == row["signer"]
    state = exposure(hold.folder(), hold.root)
    assert (state["unseals"], state["revealed"], state["chain_ok"]) == (1, 2, True)


def test_the_budget_is_enforced_at_unseal_and_checked_by_promote(hold, capsys) -> None:
    assert hold.seal(capsys)[0] == 0
    assert hold.unseal(capsys, "--items", "0,1,2")[0] == 0
    code, row = hold.unseal(capsys, "--items", "3,4")  # 5 items > 4
    assert code == 1 and codes(row) == {"holdout.budget-exceeded"}
    assert hold.unseal(capsys, "--items", "1,3")[0] == 0  # 2 unseals, 4 items: at the cap
    assert promote_refusals([hold.folder()], hold.root) == []
    code, row = hold.unseal(capsys, "--items", "0")
    assert code == 1 and codes(row) == {"holdout.budget-exceeded"}
    code, row = hold.unseal(capsys, "--items", "0", "--exceed-budget")
    assert code == 0 and row["over_budget"] is True
    found = promote_refusals([hold.folder()], hold.root)
    assert [r["code"] for r in found] == ["promote.holdout-exposed"]
    code, row = tine(capsys, "dataset", "exposure", hold.folder().as_posix(), "--repo",
                     hold.root.as_posix(), "--json")  # fmt: skip
    assert code == 1 and row["over_budget"] is True and row["unseals"] == 3


def test_a_deleted_access_record_breaks_the_chain(hold: Hold, capsys) -> None:
    assert hold.seal(capsys, unseals=5, items=6)[0] == 0
    for _ in range(3):
        assert hold.unseal(capsys, "--items", "0")[0] == 0
    (hold.folder() / "access" / "000001.json").unlink()
    assert exposure(hold.folder(), hold.root)["chain_ok"] is False
    assert [r["code"] for r in promote_refusals([hold.folder()], hold.root)] == [
        "promote.holdout-exposed"]  # fmt: skip
    code, row = hold.unseal(capsys, "--items", "1")
    assert code == 1 and codes(row) == {"holdout.chain"}


def test_items_open_only_with_the_seal_key_and_in_their_slot(hold, capsys) -> None:
    assert hold.seal(capsys)[0] == 0
    items = hold.folder() / "items"
    with pytest.raises(HoldoutError, match="does not open"):
        open_items(hold.folder(), b"\x00" * 32, [0])
    first, second = (items / "000000.sealed").read_bytes(), (items / "000001.sealed").read_bytes()
    (items / "000000.sealed").write_bytes(second)
    (items / "000001.sealed").write_bytes(first)
    master = Path(hold.seal_key).read_bytes()
    with pytest.raises(HoldoutError, match="does not open"):
        open_items(hold.folder(), master, [0])


def _exposure(hold: Hold, capsys, name: str) -> tuple[int, dict]:
    return tine(
        capsys,
        "dataset",
        "exposure",
        hold.folder(name).as_posix(),
        "--chain",
        hold.folder().as_posix(),
        "--repo",
        hold.root.as_posix(),
        "--json",
    )


def test_rotation_chains_each_generation_to_the_one_before(hold, capsys) -> None:
    assert hold.seal(capsys)[0] == 0
    code, row = hold.seal(capsys, "h2", "--rotate-from", hold.folder().as_posix())
    assert code == 0 and row["generation"] == 2 and row["previous"] == load(hold.folder())[
        "claim"]["root"]  # fmt: skip
    code, row = _exposure(hold, capsys, "h2")
    assert code == 0 and [link["generation"] for link in row["chain"]] == [1, 2]
    assert hold.seal(capsys, "h3")[0] == 0  # generation 1 again: not a successor of h1
    code, row = _exposure(hold, capsys, "h3")
    assert code == 1 and codes(row) == {"holdout.chain"}


def test_promote_refuses_an_exposed_sealed_holdout(hold: Hold, tmp_path, capsys) -> None:
    from tests.promote_helpers import RUN_B
    from tests.test_058_promote import Room, _codes, _good

    assert hold.seal(capsys, unseals=1, items=6)[0] == 0
    assert hold.unseal(capsys)[0] == 0
    sealed = ["--sealed-holdout", hold.folder().as_posix(), "--repo", hold.root.as_posix()]
    for name, exceeded in (("within", False), ("over", True)):
        if exceeded:
            assert hold.unseal(capsys, "--exceed-budget", out="again.jsonl")[0] == 0
        (tmp_path / name).mkdir()
        room = Room(tmp_path / name)
        code, row = room.promote(capsys, RUN_B, *_good(room, capsys), *sealed)
        if exceeded:
            assert code == 1 and _codes(row) == {"promote.holdout-exposed"}
        else:
            assert code == 0, row.get("refusals")
