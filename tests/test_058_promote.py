"""0.58: ``tine promote TARGET --baseline LABEL``, the signed promotion gate.

A label moves only on trusted, signed eval verdicts that beat the baseline
under the policy's test (minimum n, a holdout), with approvals from listed
approvers, under the budget cap and under the label's admission policy.
Each refusal is named. ``--revert`` and a canary regression write a signed
decision; the promotion writes the existing admission VSA.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _schemas, cli
from tests.promote_helpers import (
    APPROVER,
    AT,
    EVALER,
    PROMOTER,
    RUN_A,
    RUN_B,
    RUN_C,
    fingerprint,
    make_eval,
    policy,
    write_key,
)

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    out = capsys.readouterr().out
    document = json.loads(out) if out.strip().startswith("{") else {}
    if document:
        assert _schemas.validate_output(document) == [], document
    return code, document


class Room:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.promoter = write_key(base / "promoter.key", PROMOTER)
        self.approver = write_key(base / "approver.key", APPROVER)
        self.evaler = write_key(base / "evaler.key", EVALER)
        self.state = base / "state"

    def evals(self, name: str, run: str, passing, **kw) -> Path:
        return make_eval(self.base / name, run, passing, **kw)

    def approve(self, capsys, run: str, label: str = "prod", seed: Path | None = None) -> Path:
        out = self.base / f"approval-{run[-4:]}-{label}.json"
        code, row = _tine(capsys, "promote", run, "--baseline", label, "--approve", "--key",
                          (seed or self.approver).as_posix(), "--out", out.as_posix(),
                          "--state", self.state.as_posix(), "--at", AT, "--json")  # fmt: skip
        assert code == 0, row["refusals"]
        return out

    def promote(self, capsys, run: str, *extra: str, label: str = "prod",
                pol: Path | None = None, out: str = "out") -> tuple[int, dict]:  # fmt: skip
        return _tine(capsys, "promote", run, "--baseline", label, "--key",
                     self.promoter.as_posix(), "--policy", (pol or policy(self.base)).as_posix(),
                     "--state", self.state.as_posix(), "--out", (self.base / out).as_posix(),
                     "--at", AT, "--json", *extra)  # fmt: skip


@pytest.fixture
def room(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    return Room(tmp_path)


def _good(room: Room, capsys, run: str = RUN_B) -> list[str]:
    base = room.evals("base", RUN_A, lambda i: i % 2 == 0)
    cand = room.evals(f"cand-{run[-1]}", run, lambda i: i % 10 != 0)
    hbase = room.evals("hbase", RUN_A, lambda i: i % 2 == 0, dataset="hold")
    hcand = room.evals(f"hcand-{run[-1]}", run, lambda i: i % 10 != 0, dataset="hold")
    return ["--baseline-evals", base.as_posix(), "--evals", cand.as_posix(), "--holdout",
            hbase.as_posix(), hcand.as_posix(), "--approval",
            room.approve(capsys, run).as_posix(), "--spent", "1"]  # fmt: skip


def _codes(row: dict) -> set[str]:
    return {item["code"] for item in row["refusals"]}


def test_a_candidate_that_beats_the_baseline_is_promoted_with_a_vsa(room, capsys):
    code, row = room.promote(capsys, RUN_B, *_good(room, capsys))
    assert code == 0, row.get("refusals")
    assert (row["action"], row["current"], row["previous"]) == ("promote", RUN_B, None)
    out = room.base / "out"
    vsa = json.loads((out / "vsa.json").read_text("utf-8"))
    assert vsa["payloadType"] == "application/vnd.in-toto+json"
    decision = json.loads((out / "decision.json").read_text("utf-8"))
    assert decision["claim"]["schema"] == "opentine.promotion-decision/1"
    assert decision["claim"]["action"] == "promote" and decision["target_id"] == RUN_B
    uris = [i["uri"] for i in row["inputs"]]
    assert sum(u.startswith("eval:") for u in uris) == 4 and "compare:holdout" in uris
    assert any(u.startswith("approval:") for u in uris)
    state = json.loads((room.state / "prod.json").read_text("utf-8"))
    assert state["current"] == RUN_B


def test_n_below_the_minimum_is_refused_by_name(room, capsys):
    base = room.evals("b20", RUN_A, lambda i: i % 2 == 0, n=20)
    cand = room.evals("c20", RUN_B, lambda i: True, n=20)
    code, row = room.promote(capsys, RUN_B, "--baseline-evals", base.as_posix(), "--evals",
                             cand.as_posix(), "--approval",
                             room.approve(capsys, RUN_B).as_posix(), "--spent", "0",
                             pol=policy(room.base, require_holdout=False))  # fmt: skip
    assert code == 1 and row["action"] == "refused"
    assert _codes(row) == {"promote.n-below-minimum"}
    assert not (room.state / "prod.json").exists()


def test_an_interval_crossing_zero_is_refused_by_name(room, capsys):
    base = room.evals("same-a", RUN_A, lambda i: i % 2 == 0)
    cand = room.evals("same-b", RUN_B, lambda i: i % 2 == 1)
    code, row = room.promote(capsys, RUN_B, "--baseline-evals", base.as_posix(), "--evals",
                             cand.as_posix(), "--approval",
                             room.approve(capsys, RUN_B).as_posix(), "--spent", "0",
                             pol=policy(room.base, require_holdout=False))  # fmt: skip
    assert code == 1 and _codes(row) == {"promote.ci-crosses-zero"}


def test_permutation_without_a_gain_is_not_significant(room, capsys):
    base = room.evals("pa", RUN_A, lambda i: i % 2 == 0)
    cand = room.evals("pb", RUN_B, lambda i: i % 2 == 0 or i == 1)
    code, row = room.promote(capsys, RUN_B, "--baseline-evals", base.as_posix(), "--evals",
                             cand.as_posix(), "--approval",
                             room.approve(capsys, RUN_B).as_posix(), "--spent", "0",
                             pol=policy(room.base, require_holdout=False,
                                        test="permutation"))  # fmt: skip
    assert code == 1 and _codes(row) == {"promote.not-significant"}


def test_missing_approver_over_budget_and_missing_holdout_are_each_named(room, capsys):
    args = _good(room, capsys)
    cut = args.index("--holdout")
    without = args[:cut] + ["--approval", room.approve(capsys, RUN_B, seed=room.evaler).as_posix(),
                            "--spent", "10.01"]  # fmt: skip
    code, row = room.promote(capsys, RUN_B, *without)
    assert code == 1
    assert _codes(row) == {"promote.missing-approver", "promote.over-budget",
                           "promote.missing-holdout"}  # fmt: skip


def test_an_approval_for_another_label_does_not_count(room, capsys):
    args = _good(room, capsys)
    at = args.index("--approval")
    args[at + 1] = room.approve(capsys, RUN_B, label="staging").as_posix()
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 1 and _codes(row) == {"promote.missing-approver"}


def test_untrusted_eval_signers_and_uncovered_labels_are_refused(room, capsys):
    args = _good(room, capsys)
    stranger = room.evals("stranger", RUN_B, lambda i: True, signer=APPROVER)
    args[args.index("--evals") + 1] = stranger.as_posix()
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 1 and "promote.untrusted-eval" in _codes(row)
    admission = {"kind": "opentine.admission-policy", "version": 1, "refs": ["labels/staging"]}
    pol = policy(room.base)
    (room.base / "labels.json").write_bytes(json.dumps(admission).encode())
    code, row = room.promote(capsys, RUN_B, *_good(room, capsys), pol=pol)
    assert code == 1 and _codes(row) == {"promote.label-policy"}


def test_promote_revert_promote_moves_the_label_and_signs_each_decision(room, capsys):
    code, row = room.promote(capsys, RUN_B, *_good(room, capsys), out="one")
    assert code == 0, row.get("refusals")
    code, row = room.promote(capsys, RUN_B, "--revert", "--reason", "rollback", out="two")
    assert code == 0, row.get("refusals")
    assert (row["action"], row["current"]) == ("revert", None)
    decision = json.loads((room.base / "two" / "decision.json").read_text("utf-8"))
    assert decision["claim"]["reason"] == "rollback"
    code, row = room.promote(capsys, RUN_C, *_good(room, capsys, RUN_C), out="three")
    assert code == 0, row.get("refusals")
    state = json.loads((room.state / "prod.json").read_text("utf-8"))
    assert [h["action"] for h in state["history"]] == ["promote", "revert", "promote"]
    assert state["current"] == RUN_C
    code, row = room.promote(capsys, RUN_B, "--revert", out="four")
    assert code == 1 and _codes(row) == {"promote.not-current"}


def test_a_signed_canary_regression_reverts_automatically(room, capsys):
    code, _ = room.promote(capsys, RUN_B, *_good(room, capsys), out="one")
    assert code == 0
    base = room.base / "base"
    fine = room.evals("canary-ok", RUN_B, lambda i: i % 2 == 0)
    code, row = room.promote(capsys, RUN_B, "--canary", fine.as_posix(), "--baseline-evals",
                             base.as_posix(), out="c1")  # fmt: skip
    assert code == 0 and (row["action"], row["current"]) == ("canary", RUN_B)
    bad = room.evals("canary-bad", RUN_B, lambda i: i % 10 == 0)
    code, row = room.promote(capsys, RUN_B, "--canary", bad.as_posix(), "--baseline-evals",
                             base.as_posix(), out="c2")  # fmt: skip
    assert code == 0 and (row["action"], row["current"]) == ("revert", None)
    assert row["reason"] == "canary-regression"
    assert row["stats"]["canary"]["regressions"]
    decision = json.loads((room.base / "c2" / "decision.json").read_text("utf-8"))
    assert decision["claim"]["reason"] == "canary-regression"


def test_the_legacy_promotions_ref_form_still_needs_a_name(room, capsys):
    with pytest.raises(SystemExit):
        cli.main(["promote", RUN_B, "--repo", room.base.as_posix()])


def test_the_promoting_key_cannot_approve_itself(room, capsys):
    pol = policy(room.base, approvers=[fingerprint(PROMOTER), fingerprint(APPROVER)])
    args = _good(room, capsys)
    at = args.index("--approval")
    args[at + 1] = room.approve(capsys, RUN_B, seed=room.promoter).as_posix()
    code, row = room.promote(capsys, RUN_B, *args, pol=pol)
    assert code == 1 and _codes(row) == {"promote.missing-approver"}


def test_a_candidate_cannot_drop_the_items_it_fails(room, capsys):
    args = _good(room, capsys)
    at = args.index("--evals")
    cherry = room.evals("cherry", RUN_B, lambda i: True, keep=lambda i: i % 10 != 0)
    args[at + 1] = cherry.as_posix()
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 1 and row["action"] == "refused"
    assert _codes(row) & {"promote.item-mismatch", "promote.dataset-mismatch"}


@pytest.mark.parametrize("spent", [None, "-1", "nan"])
def test_spend_must_be_declared_and_non_negative(room, capsys, spent):
    args = _good(room, capsys)
    at = args.index("--spent")
    args = args[:at] + ([] if spent is None else ["--spent", spent])
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 1 and row.get("action") != "promote" and "refusals" not in row
    assert not (room.state / "prod.json").exists()
