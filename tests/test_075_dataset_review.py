"""0.75 review: holes a loop holding only its optimizer key could use against curation."""

from __future__ import annotations

import pytest

from opentine import _containment_records as records
from opentine import _dataset_claims as dc
from opentine import _dataset_version as dv
from opentine import _transcript_flags as tf
from opentine.graph import Run, StepKind
from opentine.repository._holds import TAINT
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_075_dataset_curate import (  # noqa: F401
    AT,
    CURATOR,
    OPTIMIZER,
    SCORER,
    STRANGER,
    _cli,
    _pin,
    _run,
    keys_fixture,
    repo_fixture,
)

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

BODY = "the trajectory that gamed the reward: " + " ".join(f"step{i}" for i in range(400))


def _twin(repo, rid, body=BODY):
    run = Run(id=rid, model_info="m", user_prompt=body)
    run.add_step(StepKind.done, {"text": "done"})
    return repo.put_run(run).run_id


def _taint(repo, run):
    records.record(repo, run, {"convention": "opentine.integrity.taint", "run": run},
                   STRANGER, TAINT + run)  # fmt: skip


def test_a_renamed_copy_of_a_tainted_run_is_left_out(repo):
    _pin(repo)
    bad = _twin(repo, "orig")
    copy = _twin(repo, "renamed")
    assert bad != copy
    _taint(repo, bad)
    out = dv.curate(repo, "train", "all", CURATOR, AT)
    runs = {m["run"] for m in out["claim"]["members"]}
    assert copy not in runs and bad not in runs
    assert copy in out["claim"]["taint_filter"]["excluded"]


def test_a_near_duplicate_of_a_tainted_run_is_left_out(repo):
    _pin(repo)
    bad = _twin(repo, "orig")
    near = _twin(repo, "near", BODY + " and one more harmless line at the end")
    clean = _run(repo, 1)
    _taint(repo, bad)
    out = dv.curate(repo, "train", "all", CURATOR, AT)
    runs = {m["run"] for m in out["claim"]["members"]}
    assert runs == {clean}
    assert near in out["claim"]["taint_filter"]["excluded"]


def test_a_forged_version_cannot_become_the_previous_version(repo):
    _pin(repo)
    _run(repo, 1)
    first = dv.curate(repo, "train", "all", CURATOR, AT)
    forged = dict(first["claim"], version=7, previous=first["record"],
                  curator=records.fingerprint(OPTIMIZER))  # fmt: skip
    anchor = records.anchor(repo, "dataset", "forged")
    fake = records.record(repo, anchor, forged, OPTIMIZER, f"{dv.HOLD}version:train:7")
    nxt = dv.curate(repo, "train", "all", CURATOR, AT)
    assert nxt["claim"]["version"] == 2
    assert nxt["claim"]["previous"] == first["record"] != fake


def test_a_member_flagged_after_curation_unverifies_the_version(repo):
    _pin(repo)
    run = _run(repo, 1)
    dv.curate(repo, "train", "all", CURATOR, AT)
    assert dv.versions(repo, "train")[0]["verification"] == "verified"
    tf.record(repo, {"label": "reward-hacking", "evidence": [run], "cluster": None,
                     "backend": None, "note": "", "labelled_at": AT}, SCORER)  # fmt: skip
    state = dv.versions(repo, "train")[0]["verification"]
    assert state.startswith("unverified") and "tainted" in state


def test_an_optimizer_withdrawal_does_not_count(repo):
    _pin(repo)
    run = _run(repo, 1)
    with pytest.raises(PermissionError):
        dv.withdraw(repo, run, "drop the clean data", OPTIMIZER, AT)
    claim = {"convention": dc.WITHDRAWAL, "run": run, "reason": "x",
             "contributor": records.fingerprint(OPTIMIZER), "at": AT}  # fmt: skip
    records.record(repo, run, claim, OPTIMIZER, f"{dv.HOLD}withdrawal:{run}")
    assert dv.withdrawals(repo) == {}


@pytest.mark.parametrize("raw", ['{"claim": 1, "claim": {}}', '{"x": NaN}'])
def test_verify_version_file_refuses_duplicate_keys_and_nan(tmp_path, capsys, raw):
    path = tmp_path / "p.json"
    path.write_bytes(raw.encode())
    code, _ = _cli(capsys, "dataset", "verify-version", "--file", str(path), "--json")
    assert code != 0
