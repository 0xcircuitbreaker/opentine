"""0.89: judge ensembles count copies of one judge once and refuse a dependent ensemble."""

from __future__ import annotations

from fractions import Fraction

import pytest

from opentine import _judge_provenance, _schemas
from opentine._judge_ensemble import aggregate, independence, similarity
from tests.judge_helpers import fake_models, judge_room  # noqa: F401
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.query_helpers import tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
PROMPT = ("You are a careful grader. Read the question {input}, the reference {expected} and "
          "the answer {output}. Decide whether the answer is right. Labels: {labels}.")  # fmt: skip


def member(model: str, prompt: str = PROMPT, lineage: str | None = None) -> dict:
    return {"provenance": _judge_provenance.build(model, prompt), "prompt": prompt,
            "lineage": lineage}  # fmt: skip


def lab(value: str | None, status: str = "label", p: str | None = None) -> dict:
    return {"status": status, "label": value, "probability": p}


def test_copies_forks_and_shared_lineage_collapse_into_one_group():
    fork = PROMPT.replace("careful", "very careful")
    members = [
        member("openai:x"),
        member("openai:x"),  # an exact copy
        member("anthropic:y", fork),  # a fork with a small edit
        member("ollama:z", "Grade strictly. Q={input} A={output} R={expected}", "loop-7"),
        member("vllm:w", "Is {output} a correct reply to {input}? Say {labels}.", "loop-7"),
    ]
    found = independence(members, min_independent=2)
    assert found["independent"] == 2 and found["groups"] == [[0, 1, 2], [3, 4]]
    because = {tuple(link["members"]): link["because"] for link in found["links"]}
    assert because[(0, 1)] == ["model", "prompt_digest"]
    assert because[(0, 2)] == ["prompt_similar"] and because[(3, 4)] == ["lineage"]
    assert independence(members, min_independent=3)["findings"][0]["code"] == (
        "fail:judge.ensemble-not-independent"
    )


def test_similarity_separates_forks_from_unrelated_prompts():
    assert similarity(PROMPT, PROMPT.replace("careful", "very careful")) >= Fraction(4, 5)
    assert similarity(PROMPT, "Rate the essay for style only.") < Fraction(1, 5)
    assert similarity(PROMPT, PROMPT.upper().replace(" ", "  ")) == 1  # case and spacing folded


def test_copies_of_one_judge_cannot_outvote_independent_judges():
    groups = [[0, 1, 2], [3], [4]]  # three copies of one judge, two independent judges
    outs = [lab("pass"), lab("pass"), lab("pass"), lab("fail"), lab("fail")]
    got = aggregate(outs, groups, method="majority")
    assert got["status"] == "label" and got["label"] == "fail" and got["votes"] == 3


def test_ties_abstains_and_errors_never_become_a_label():
    groups = [[0], [1], [2], [3]]
    tie = aggregate([lab("pass"), lab("fail"), lab(None, "abstain"), lab(None, "error")], groups,
                    max_abstain=Fraction(1))  # fmt: skip
    assert tie["status"] == "abstain"
    mostly = aggregate([lab("pass"), lab(None, "abstain"), lab(None, "abstain"),
                        lab(None, "error")], groups)  # fmt: skip
    assert mostly["status"] == "abstain"  # 3 of 4 groups declined: the ensemble did not decide
    inner = aggregate([lab("pass"), lab("fail")], [[0, 1]])  # a split inside one group
    assert inner["status"] == "abstain"


def test_mean_and_min_use_the_positive_label():
    groups, labels = [[0], [1], [2]], ["pass", "fail"]
    outs = [lab("pass", p="0.9"), lab("pass", p="0.7"), lab("fail", p="0.8")]
    mean = aggregate(outs, groups, method="mean", positive="pass", labels=labels)
    assert mean["label"] == "pass" and mean["probability"] == "0.600000"
    low = aggregate(outs, groups, method="min", positive="pass", labels=labels)
    assert low["label"] == "fail" and low["probability"] == "0.200000"
    with pytest.raises(ValueError):
        aggregate(outs, groups, method="mean")


def test_classify_refuses_a_dependent_ensemble_before_calling_any_model(room, monkeypatch,
                                                                         capsys):  # fmt: skip
    made = fake_models(monkeypatch, {"ollama:a": lambda _t: "LABEL: pass",
                                     "ollama:b": lambda _t: "LABEL: pass"})  # fmt: skip
    base = room["base"]
    prompt = base / "p.txt"
    prompt.write_bytes(PROMPT.encode("utf-8"))
    args = ["judge", "classify", "--judge", "ollama:a", "--judge", "ollama:b", "--labels",
            "pass,fail", "--items", (base / "items.jsonl").as_posix(), "--prompt",
            prompt.as_posix(), "--runs-dir", (base / "runs").as_posix()]  # fmt: skip
    code, out = tine(capsys, *args)
    assert code == 1, out
    _schemas.validate(out, "tine-cli-judge-1")
    assert out["independence"]["findings"][0]["code"] == "fail:judge.ensemble-not-independent"
    assert out["rows"] == [] and all(f.calls == 0 for f in made.values())


def test_classify_runs_an_independent_ensemble(room, monkeypatch, capsys):
    fake_models(monkeypatch, {"ollama:a": lambda _t: "LABEL: pass\nPROBABILITY: 0.9",
                              "openai:b": lambda _t: "LABEL: fail",
                              "vllm:c": lambda _t: "LABEL: pass"})  # fmt: skip
    base = room["base"]
    p1, p2 = base / "p1.txt", base / "p2.txt"
    p1.write_bytes(PROMPT.encode("utf-8"))
    p2.write_bytes(b"Is {output} right for {input} given {expected}? Answer with {labels}.")
    code, out = tine(capsys, "judge", "classify", "--judge", "ollama:a", "--judge", "openai:b",
                     "--judge", "vllm:c", "--prompt", p1.as_posix(), "--prompt", p2.as_posix(),
                     "--prompt", p1.as_posix(), "--labels", "pass,fail", "--items",
                     (base / "items.jsonl").as_posix(), "--runs-dir",
                     (base / "runs").as_posix())  # fmt: skip
    # members 0 and 2 share a prompt: two groups, and the copy counts once (a tie: abstain)
    assert code == 0, out
    assert out["independence"]["groups"] == [[0, 2], [1]]
    assert out["counts"] == {"label": 0, "abstain": 20, "error": 0}
    assert all(len(r["members"]) == 3 for r in out["rows"])
