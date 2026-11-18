"""0.60 red-team: a loop with only its own key tries to reset budgets and dodge checks.

Each test plays one attack and asserts the refusal. No wall-clock time is used.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Run, StepKind
from opentine._holdout import HoldoutError, dump, sign
from opentine._holdout_access import exposure, promote_refusals, run_text, touched
from tests.holdout_helpers import DATASET, ITEMS, OPTIMIZER, Hold, tine
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.promote_helpers import AT, key

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")
CANARY = "c4a7f19e0b2d4e6f8a1c3e5b7d9f0a2c"


@pytest.fixture
def hold(tmp_path: Path, capsys) -> Hold:
    made = Hold(tmp_path)
    assert made.seal(capsys, unseals=1, items=6)[0] == 0
    return made


def _run(hold: Hold, name: str, text: str) -> str:
    run = Run(id=name, user_prompt="solve the task")
    run.add_step(StepKind.think, {"text": text}, {"answer": "done"})
    return hold.repo.put_run(run).run_id


def test_a_commitment_re_signed_with_a_bigger_budget_counts_for_nothing(hold, capsys):
    assert hold.unseal(capsys, run="r1")[0] == 0
    assert hold.unseal(capsys, "--exceed-budget", run="r2", out="b.jsonl")[0] == 0
    assert promote_refusals([hold.folder()], hold.root)  # exposed
    path = hold.folder() / "commitment.json"
    doc = json.loads(path.read_bytes().decode("utf-8"))
    claim = {**doc["claim"], "budget": {"max_unseals": 10**6, "max_items": 10**6}}
    dump(path, sign(key(OPTIMIZER), claim, doc["target_id"], AT))
    with pytest.raises(HoldoutError, match="dataset-role"):
        exposure(hold.folder(), hold.root)
    found = promote_refusals([hold.folder()], hold.root)
    assert [r["code"] for r in found] == ["promote.holdout-exposed"]
    assert hold.unseal(capsys, run="r3", out="c.jsonl")[0] == 1


@pytest.mark.parametrize("lengths", ['{"%s": NaN}', '{"%s": Infinity}', '{"%s": -1}',
                                     '{"%s": "999"}'])  # fmt: skip
def test_a_bogus_code_length_does_not_pass(hold, capsys, lengths):
    code, row = tine(capsys, "dataset", "canary-add", CANARY, "--entropy-bits", "128",
                     "--key", hold.keys[DATASET], "--repo", hold.root.as_posix(), "--at", AT,
                     "--json")  # fmt: skip
    assert code == 0, row
    path = hold.base / "lengths.json"
    path.write_bytes(lengths.replace("%s", row["canary"]["canary_sha256"]).encode("utf-8"))
    status, _ = tine(capsys, "dataset", "canary-check", path.as_posix(), "--repo",
                     hold.root.as_posix(), "--json")  # fmt: skip
    assert status != 0  # an error, never a pass


def test_an_item_with_its_spacing_and_case_changed_is_touched(hold):
    squashed = ITEMS[4]["expected"].upper().replace(" ", "")
    run = hold.repo.load_run(_run(hold, "squash", f"answer key: {squashed}"))
    found = touched(hold.folder(), ITEMS, {"squash": run_text(run)}, hold.root)
    assert [f["code"] for f in found] == ["eval.holdout-touched"]
    assert "h-04 in clear" in found[0]["detail"]


def test_an_optimizer_key_cannot_unseal_or_forge_a_record_that_counts(hold, capsys):
    assert hold.unseal(capsys, seed=OPTIMIZER)[0] == 1
    root = exposure(hold.folder(), hold.root)["root"]
    forged = {"schema": "opentine.holdout.access/1", "root": root, "sequence": 0,
              "previous": None, "run": "x", "why": "y", "purpose": "eval", "items": [],
              "over_budget": False}  # fmt: skip
    dump(hold.folder() / "access" / "000000.json", sign(key(OPTIMIZER), forged, "t", AT))
    assert exposure(hold.folder(), hold.root)["unseals"] == 0
