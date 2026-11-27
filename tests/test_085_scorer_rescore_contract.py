"""0.85: trusted re-scoring, evaluator contracts, the introspection lint, promotion."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from opentine import _promote_scorer as promote
from opentine import _scorer_closure as closure
from opentine._scorer_lint import lint, lint_source
from opentine._scorer_rescore import verify_report
from tests.scorer_isolation_helpers import HELPER, isolated_eval, room, run_json, scorer

pytestmark = pytest.mark.filterwarnings("ignore:.*plaintext-hex private key")
__all__ = ["room"]

# Fraction of positions where the output list matches the expected list.
FRACTION = ("def score(output, item):\n    want = item['expected']\n"
            "    got = output{cut}\n    want = want{cut}\n"
            "    return sum(a == b for a, b in zip(got, want)) / len(want)\n")  # fmt: skip


def _rescore(capsys, *extra: str) -> tuple[int, dict]:
    return run_json(capsys, "eval", "rescore", "ev", "--dataset", "d.jsonl", "--key", "k.key",
                    *extra)  # fmt: skip


def test_a_rescore_of_the_same_outputs_agrees_and_is_signed(capsys, room):
    isolated_eval(capsys, room)
    status, out = _rescore(capsys, "--out", "r.json")
    assert status == 0 and out["ok"] and out["report"]["verdict"] == "agree"
    report = json.loads((room / "r.json").read_bytes())
    assert verify_report(report) is None and report["closure_agree"]
    assert report["closure"] == closure.closure_digest(closure.read(room / "ev"))
    report["verdict"] = "disagree"
    assert verify_report(report) is not None


def test_a_tampered_cached_result_disagrees_and_the_disagreement_is_signed(capsys, room):
    rows = [json.loads(x) for x in (room / "d.jsonl").read_bytes().splitlines()]
    cached = "".join(json.dumps({"id": r["id"], "output": r["expected"], "run": "run:x"}) + "\n"
                     for r in rows)  # fmt: skip
    (room / "cache.jsonl").write_bytes(cached.encode("utf-8"))  # every answer "right"
    isolated_eval(capsys, room, "ev", "--outputs", "cache.jsonl")
    status, out = _rescore(capsys)  # the dataset's real outputs
    report = out["report"]
    assert status != 0 and report["verdict"] == "disagree" and report["closure_agree"]
    assert report["disagreed"] == sum(1 for r in rows if r["output"] != r["expected"])
    assert verify_report(report) is None


def test_a_changed_helper_makes_the_rescore_disagree_on_the_closure(capsys, room):
    isolated_eval(capsys, room)
    (room / "sc" / "helper.py").write_bytes(HELPER + b"# edited\n")
    status, out = _rescore(capsys)
    assert status != 0 and not out["report"]["closure_agree"]
    assert out["report"]["verdict"] == "disagree" and out["report"]["disagreed"] == 0


def test_an_in_process_eval_cannot_be_trusted_rescored(capsys, room):
    run_json(capsys, "eval", "run", "d.jsonl", "--scorer", "exact", "--key", "k.key", "--out", "ev")
    status, out = _rescore(capsys)
    assert status != 0 and "scorer.json" in out["error"]["message"]


def _list_room(room: Path, cut: str) -> str:
    rows = [
        {"id": "a", "input": "q", "expected": [1, 2, 3, 4], "output": [1, 2, 3, 4], "run": "run:x"},
        {"id": "b", "input": "q", "expected": [1, 2, 3, 4], "output": [9, 9, 9, 4], "run": "run:x"},
    ]
    (room / "l.jsonl").write_bytes("".join(json.dumps(r) + "\n" for r in rows).encode("utf-8"))
    return scorer(room, "frac", FRACTION.format(cut=cut))


@pytest.mark.parametrize("isolate", [True, False])
def test_a_dropped_slice_in_the_scorer_fails_its_contract(capsys, room, isolate):
    contract = {"convention": "opentine.scorer-contract/1", "deterministic": True,
                "anchors": [{"item": {"id": "x", "expected": [1, 2]}, "output": [0, 2],
                             "score": 0.5}]}  # fmt: skip
    (room / "c.json").write_bytes(json.dumps(contract).encode("utf-8"))
    flags = ("--isolate",) if isolate else ()
    argv = ("eval", "run", "l.jsonl", "--key", "k.key", "--contract", "c.json", *flags)
    status, out = run_json(capsys, *argv, "--scorer", _list_room(room, ""), "--out", "ok")
    assert status == 0, out
    if isolate:
        digest = "sha256:" + hashlib.sha256((room / "c.json").read_bytes()).hexdigest()
        assert closure.read(room / "ok")["contract"] == digest
    # The mutation keeps only the last element, so "b" would score 1 instead of 0.25.
    status, out = run_json(capsys, *argv, "--scorer", _list_room(room, "[-1:]"), "--out", "bad")
    assert status == 1 and out["refusals"][0]["code"] == "scorer.contract"
    assert not (room / "bad").exists()


def test_contract_shape_length_and_determinism_checks(capsys, room):
    spec = _list_room(room, "")
    for clause in ({"length_relation": {"field": "expected", "relation": "eq"}},
                   {"output_length": {"min": 5}},
                   {"output_schema": {"type": "array", "items": {"type": "string"}}}):  # fmt: skip
        doc = {"convention": "opentine.scorer-contract/1", **clause}
        (room / "c.json").write_bytes(json.dumps(doc).encode("utf-8"))
        rows = [json.loads(x) for x in (room / "l.jsonl").read_bytes().splitlines()]
        rows[1]["output"] = [4]  # truncated output: a different length
        (room / "l.jsonl").write_bytes("".join(json.dumps(r) + "\n" for r in rows).encode())
        status, out = run_json(capsys, "eval", "run", "l.jsonl", "--scorer", spec, "--key",
                               "k.key", "--contract", "c.json", "--out", "x")  # fmt: skip
        assert status == 1 and out["refusals"][0]["code"] == "scorer.contract", clause
    flaky = scorer(room, "flaky", "import random\n\ndef score(output, item):\n"
                   "    return random.random()\n")  # fmt: skip
    doc = {"convention": "opentine.scorer-contract/1", "deterministic": True}
    (room / "c.json").write_bytes(json.dumps(doc).encode("utf-8"))
    status, out = run_json(capsys, "eval", "run", "d.jsonl", "--scorer", flaky, "--isolate",
                           "--key", "k.key", "--contract", "c.json", "--out", "x")  # fmt: skip
    assert status == 1 and "twice" in out["refusals"][0]["detail"]


STACK_WALKER = """import inspect, sys, gc

def score(output, item):
    frame = sys._getframe(1)
    answer = frame.f_back.f_locals.get("expected")
    outer = inspect.stack()
    refs = gc.get_referrers(item)
    grader = open("tests/test_grader.py").read()
    return eval("1") if getattr(item, "x" + "y", None) else answer
"""


def test_the_lint_flags_stack_walking_grader_reads_and_dynamic_code(room):
    found = {f["code"] for f in lint_source(STACK_WALKER, "s.py", ["grade_it.py"])}
    assert found == {
        "advisory:introspection.stack",
        "advisory:introspection.gc",
        "advisory:introspection.dynamic",
        "advisory:introspection.grader-read",
    }
    named = lint_source("PATH = 'graders/grade_it.py'\n", "c.py", ["grade_it.py"])
    assert [f["code"] for f in named] == ["advisory:introspection.grader-read"]
    assert lint_source((room / "sc" / "good.py").read_text("utf-8"), "good.py", []) == []
    assert lint([room / "sc" / "helper.py"])["findings"] == []


def test_the_lint_is_advisory_unless_strict(capsys, room):
    (room / "w.py").write_bytes(STACK_WALKER.encode("utf-8"))
    status, out = run_json(capsys, "eval", "lint", "w.py")
    assert status == 0 and out["ok"] and out["findings"]
    status, out = run_json(capsys, "eval", "lint", "w.py", "--strict")
    assert status != 0 and not out["ok"]


def test_promotion_flags_in_process_scorers_and_refuses_them_only_when_pinned(capsys, room):
    isolated_eval(capsys, room, "iso")
    run_json(capsys, "eval", "run", "d.jsonl", "--scorer", "python:sc/helper.py:same",
             "--key", "k.key", "--out", "inproc")  # fmt: skip
    run_json(capsys, "eval", "run", "d.jsonl", "--scorer", "exact", "--key", "k.key",
             "--out", "builtin")  # fmt: skip
    assert promote.in_process(room / "inproc") and not promote.in_process(room / "iso")
    assert not promote.in_process(room / "builtin")
    folders = {"baseline": room / "builtin", "candidate": room / "inproc"}
    policy: dict = {}
    promote.check_policy(policy)
    refused, advisories = promote.isolation(policy, folders)
    assert refused == [] and [a["code"] for a in advisories] == ["advisory:scorer.in-process"]
    for given in ({"scorer_isolation": "required"}, {"profile": "rsi"}):
        promote.check_policy(given)
        refused, advisories = promote.isolation(given, folders)
        assert [r["code"] for r in refused] == ["promote.scorer-in-process"] and not advisories
    assert promote.isolation({"scorer_isolation": "required"},
                             {"candidate": room / "iso"}) == ([], [])  # fmt: skip
    for bad in ({"profile": "rsi", "scorer_isolation": "advisory"}, {"profile": "x"},
                {"scorer_isolation": "sometimes"}):  # fmt: skip
        with pytest.raises(ValueError):
            promote.check_policy(bad)
