"""0.86: ``tine promote --plan``: pre-registered, selection-adjusted promotion.

An adversarial loop tries many candidates, edits the plan after seeing results,
hides candidates from the lineage, picks its own seed or drops hard items. Each
attempt is refused by name; an honest plan promotes and signs its analysis.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _schemas, cli
from tests.plan_helpers import items, plan_sha, run, write_plan
from tests.promote_helpers import (
    APPROVER,
    AT,
    PROMOTER,
    RUN_A,
    RUN_B,
    key,
    policy,
    write_key,
)

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")
STRONG = (lambda i, e: i % 2 == 0, lambda i, e: i % 10 != 0)  # baseline 50%, candidate 90%
MARGINAL = (lambda i, e: i % 2 == 0, lambda i, e: i % 2 == 0 or i % 8 == 1)  # +12.5%


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
        self.base, self.state = base, base / "state"
        self.repo = base / "repo"
        (self.repo / ".tine").mkdir(parents=True)
        self.promoter = write_key(base / "promoter.key", PROMOTER)
        self.approver = write_key(base / "approver.key", APPROVER)
        self.rows = items()

    def pair(self, passing=STRONG, plan: Path | None = None, **kw) -> list[str]:
        base = run(self.base / "base", self.rows, RUN_A, passing[0])
        cand = run(self.base / "cand", self.rows, RUN_B, passing[1], plan=plan, **kw)
        return ["--baseline-evals", base.as_posix(), "--evals", cand.as_posix()]

    def promote(self, capsys, *extra: str, **pol) -> tuple[int, dict]:
        approval = self.base / "approval.json"
        _tine(capsys, "promote", RUN_B, "--baseline", "prod", "--approve", "--key",
              self.approver.as_posix(), "--out", approval.as_posix(), "--state",
              self.state.as_posix(), "--at", AT, "--json")  # fmt: skip
        pol.setdefault("require_holdout", False)
        return _tine(capsys, "promote", RUN_B, "--baseline", "prod", "--key",
                     self.promoter.as_posix(), "--policy", policy(self.base, **pol).as_posix(),
                     "--state", self.state.as_posix(), "--out", (self.base / "out").as_posix(),
                     "--repo", self.repo.as_posix(), "--approval", approval.as_posix(),
                     "--spent", "1", "--at", AT, "--json", *extra)  # fmt: skip


@pytest.fixture
def room(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    monkeypatch.delenv("OPENTINE_TRUST_OWNER", raising=False)
    monkeypatch.delenv("OPENTINE_TRUST_BUNDLE", raising=False)
    return Room(tmp_path)


def _codes(row: dict) -> set[str]:
    return {item["code"] for item in row.get("refusals", [])}


def _plan_args(plan: Path, reveal: Path | None) -> list[str]:
    return ["--plan", plan.as_posix(), *(["--reveal", reveal.as_posix()] if reveal else [])]


def test_an_honest_plan_promotes_and_signs_its_analysis(room, capsys):
    plan, reveal = write_plan(room.base, room.rows)
    code, row = room.promote(capsys, *room.pair(plan=plan), *_plan_args(plan, reveal))
    assert code == 0, row.get("refusals")
    assert row["plan"]["plan_sha256"] == plan_sha(plan)
    assert row["plan"]["candidates"] == 1 and row["plan"]["analysis"]["passed"] is True
    assert row["plan"]["coverage"] == {"planned": 40, "scored": 40, "skipped": [], "errored": []}
    decision = json.loads((room.base / "out" / "decision.json").read_bytes())
    assert decision["claim"]["plan"]["seed"] == row["plan"]["seed"]
    state = json.loads((room.state / "prod.json").read_bytes())
    assert state["history"][-1]["plan_sha256"] == plan_sha(plan)


def test_without_a_plan_the_promotion_is_advisory_by_default(room, capsys):
    code, row = room.promote(capsys, *room.pair())
    assert code == 0, row.get("refusals")
    assert "advisory:promote.no-plan" in {a["code"] for a in row["advisories"]}


def test_a_policy_can_require_a_plan(room, capsys):
    code, row = room.promote(capsys, *room.pair(), require_plan=True)
    assert code == 1 and "promote.plan-missing" in _codes(row)


def test_many_candidates_need_the_corrected_test(room, capsys):
    plan, reveal = write_plan(room.base, room.rows, max_candidates=200, resamples=2000)
    code, row = room.promote(capsys, *room.pair(MARGINAL, plan=plan), *_plan_args(plan, reveal))
    assert code == 1 and _codes(row) == {"promote.uncorrected"}, row  # the 0.58 test passes
    one, again = write_plan(room.base, room.rows, resamples=2000, name="one.json")
    code, row = room.promote(capsys, *room.pair(MARGINAL, plan=one), *_plan_args(one, again))
    assert code == 0, row.get("refusals")


def test_a_plan_edited_after_the_results_is_refused(room, capsys):
    plan, _ = write_plan(room.base, room.rows, max_candidates=200)
    args = room.pair(plan=plan)  # the run is bound to the 200-candidate plan
    edited, reveal = write_plan(room.base, room.rows, name="edited.json")  # backdated, m=1
    code, row = room.promote(capsys, *args, *_plan_args(edited, reveal))
    assert code == 1 and "promote.plan-mismatch" in _codes(row)


def test_a_plan_signed_after_the_verdicts_is_refused(room, capsys):
    plan, reveal = write_plan(room.base, room.rows, at="2026-11-01T12:30:00Z")
    code, row = room.promote(capsys, *room.pair(plan=plan), *_plan_args(plan, reveal))
    assert code == 1 and "promote.plan-after-outputs" in _codes(row)


def test_the_seed_is_the_committed_one(room, capsys):
    plan, _ = write_plan(room.base, room.rows)
    args = room.pair(plan=plan)
    code, row = room.promote(capsys, *args, *_plan_args(plan, None))
    assert code == 1 and "promote.seed-not-committed" in _codes(row)
    _, wrong = write_plan(room.base, room.rows, name="other.json", secret="11" * 32)
    code, row = room.promote(capsys, *args, *_plan_args(plan, wrong))
    assert code == 1 and "promote.seed-not-committed" in _codes(row)


def test_dropped_items_fall_below_the_coverage_floor(room, capsys):
    plan, reveal = write_plan(room.base, room.rows)
    hard = {f"main-{i:03d}" for i in range(0, 40, 10)}  # the items the candidate fails
    code, row = room.promote(capsys, *room.pair(plan=plan, missing=hard),
                             *_plan_args(plan, reveal), min_n=30)  # fmt: skip
    assert code == 1 and "promote.coverage" in _codes(row)


def test_hidden_candidates_cannot_lower_the_committed_count(room, capsys):
    from opentine._lineage import record

    plan, reveal = write_plan(room.base, room.rows, max_candidates=2)
    lineage = room.repo / ".tine" / "lineage"
    for n in range(3):  # three siblings of one parent: one more than the plan allows
        record(key(PROMOTER), run=RUN_B if n == 0 else "run:sha256:" + f"{n:x}" * 64,
               artifacts={"code_tree": "sha256:" + f"{n + 1:x}" * 64}, store=lineage,
               parents=["sha256:" + "9" * 64], at=AT)  # fmt: skip
    code, row = room.promote(capsys, *room.pair(plan=plan), *_plan_args(plan, reveal))
    assert code == 1 and "promote.candidates-over-plan" in _codes(row)


def test_the_rsi_profile_requires_a_plan_and_pinned_eval_signers(room, capsys):
    from tests.key_roles_helpers import pin_roles
    from tests.promote_helpers import EVALER, fingerprint

    code, row = room.promote(capsys, *room.pair(), profile="rsi")
    assert code == 1 and {"promote.plan-missing", "promote.eval-signer-role"} <= _codes(row)
    store = room.repo / ".tine"
    (store / "key-roles.toml").write_bytes(
        f'version = 1\n[roles]\nscorer = ["{fingerprint(EVALER)}"]\n'.encode()
    )
    pin_roles(store)
    plan, reveal = write_plan(room.base, room.rows)
    code, row = room.promote(capsys, *room.pair(plan=plan), *_plan_args(plan, reveal),
                             profile="rsi")  # fmt: skip
    assert code == 0, row.get("refusals")


def test_a_plan_signed_by_a_key_that_may_not_sign_evals_is_refused(room, capsys):
    plan, reveal = write_plan(room.base, room.rows, signer=PROMOTER)
    code, row = room.promote(capsys, *room.pair(plan=plan), *_plan_args(plan, reveal))
    assert code == 1 and "promote.plan-signer" in _codes(row)


def test_under_the_rsi_profile_an_optimizer_key_never_signs_evals(room, capsys):
    from tests.key_roles_helpers import pin_roles
    from tests.promote_helpers import EVALER, fingerprint

    store = room.repo / ".tine"
    who = fingerprint(EVALER)
    text = f'version = 1\n[roles]\nscorer = ["{who}"]\noptimizer = ["{who}"]\n'
    (store / "key-roles.toml").write_bytes(text.encode())
    pin_roles(store)
    plan, reveal = write_plan(room.base, room.rows)
    code, row = room.promote(capsys, *room.pair(plan=plan), *_plan_args(plan, reveal),
                             profile="rsi")  # fmt: skip
    assert code == 1 and {"promote.eval-signer-role", "promote.plan-signer"} <= _codes(row)
