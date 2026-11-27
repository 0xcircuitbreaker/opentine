"""0.86 review: an early seed reveal, Holm steps past the plan and hidden lineage records.

Each test drives :func:`opentine._promote_plan.check` directly with deterministic
evals, so it needs no wall clock and no CLI state.
"""

from __future__ import annotations

import json

import pytest

from opentine import _eval_plan as plans
from opentine import _promote_plan
from tests.plan_helpers import SECRET, items, plan_sha, run, write_plan
from tests.promote_helpers import AT, EVALER, PROMOTER, RUN_A, RUN_B, fingerprint, key

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def _setup(tmp_path, **over):
    rows = items()
    plan, reveal = write_plan(tmp_path, rows, **over)
    base = run(tmp_path / "base", rows, RUN_A, lambda i, e: i % 2 == 0)
    cand = run(tmp_path / "cand", rows, RUN_B, lambda i, e: i % 10 != 0, plan=plan)
    return rows, plan, reveal, base, cand


def _check(base, cand, plan, reveal, *, history=(), lineage=None, **pol):
    policy = {"eval_signers": [fingerprint(EVALER)], **pol}
    return _promote_plan.check(policy, candidate=RUN_B, history=list(history), baseline=base,
                               evals=cand, plan_path=plan, reveal_path=reveal, lineage=lineage,
                               store=None, folders={"candidate": cand})  # fmt: skip


def _codes(result) -> set[str]:
    return {r["code"] for r in result[0]}


def test_the_honest_case_passes(tmp_path):
    _rows, plan, reveal, base, cand = _setup(tmp_path)
    assert _codes(_check(base, cand, plan, reveal)) == set()


def test_a_seed_revealed_before_the_verdicts_is_refused(tmp_path):
    _rows, plan, _reveal, base, cand = _setup(tmp_path)
    early = tmp_path / "early.json"
    doc = json.loads(plan.read_bytes())
    plans.dump(early, plans.make_reveal(key(EVALER), doc, SECRET, "2026-11-01T11:30:00Z"))
    assert "promote.seed-not-committed" in _codes(_check(base, cand, plan, early))


def test_promotions_past_the_planned_count_are_refused_not_uncorrected(tmp_path):
    _rows, plan, reveal, base, cand = _setup(tmp_path, max_candidates=2)
    done = [{"action": "promote", "plan_sha256": plan_sha(plan)}] * 2
    result = _check(base, cand, plan, reveal, history=done)
    assert "promote.candidates-over-plan" in _codes(result)


def test_a_candidate_missing_from_a_recorded_lineage_is_refused(tmp_path):
    from opentine._lineage import record

    _rows, plan, reveal, base, cand = _setup(tmp_path, max_candidates=2)
    lineage = tmp_path / "lineage"
    record(
        key(PROMOTER),
        run="run:sha256:" + "1" * 64,
        store=lineage,
        at=AT,
        artifacts={"code_tree": "sha256:" + "2" * 64},
        parents=["sha256:" + "9" * 64],
    )
    result = _check(base, cand, plan, reveal, lineage=lineage)
    assert "promote.lineage-missing" in _codes(result)


def test_the_rsi_profile_needs_the_candidate_in_the_lineage(tmp_path):
    _rows, plan, reveal, base, cand = _setup(tmp_path)
    result = _check(base, cand, plan, reveal, lineage=tmp_path / "none", require_lineage=True)
    assert "promote.lineage-missing" in _codes(result)
