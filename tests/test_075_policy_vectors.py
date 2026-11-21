"""0.74: the policy language on the shared vectors (also run by ts/verifier/test/policy.test.ts)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _policy, _schemas
from opentine._policy_eval import check_input, evaluate
from opentine._policy_lang import PolicyError, parse

VECTORS = json.loads(
    (Path(__file__).parent / "data" / "policy_vectors.json").read_bytes().decode("utf-8")
)


def _run(case):
    inp = VECTORS["input"] if case["input"] is None else case["input"]
    try:
        check_input(inp)
        return {"outcome": "value", "value": evaluate(parse(case["expr"]), inp)}
    except PolicyError as exc:
        return {"outcome": "error", "code": exc.code}


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["id"])
def test_expression_vector(case):
    assert _run(case) == case["expect"]


@pytest.mark.parametrize("case", VECTORS["policies"], ids=lambda c: c["id"])
def test_policy_vector(case):
    result = _policy.decide(case["policy"], case.get("input", VECTORS["input"]))
    assert result["decision"] == case["decision"]
    assert [r["outcome"] for r in result["rules"]] == case["outcomes"]
    if "codes" in case:
        assert [r["code"] for r in result["rules"]] == case["codes"]


def test_the_vectors_cover_every_error_code_and_both_outcomes():
    codes = {c["expect"].get("code") for c in VECTORS["cases"]}
    assert {"policy.parse", "policy.type", "policy.no-such-key", "policy.no-such-var",
            "policy.index", "policy.steps", "policy.input"} <= codes  # fmt: skip
    values = [c["expect"].get("value") for c in VECTORS["cases"]]
    assert True in values and False in values


def test_standard_policies_are_valid_and_every_rule_parses():
    for name in _policy.standard():
        doc, _raw = _policy.load(name)
        assert _schemas.validate(doc, "opentine-policy-1")[1] == []
        for rule in doc["rules"]:
            parse(rule["expr"])


def test_the_digest_covers_params():
    doc, _raw = _policy.load("k-of-n-approvals")
    other = {**doc, "params": {"approvals": 3}}
    assert _policy.policy_digest(doc) != _policy.policy_digest(other)


def test_evaluation_counts_steps_not_time():
    from opentine._policy_eval import MAX_STEPS, Evaluator

    ev = Evaluator({"l": list(range(10))})
    assert ev.run(parse("l.all(x, x >= 0)")) is True
    assert 0 < ev.steps < MAX_STEPS
