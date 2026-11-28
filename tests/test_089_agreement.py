"""0.89: judge-vs-human agreement, the floor, validation records and the promote gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _judge_provenance, _promote_judges, _schemas
from opentine._judge_agreement import cohen, fleiss, krippendorff, report
from tests.judge_helpers import (  # noqa: F401
    OPTIMIZER,
    REV1,
    REV2,
    SCORER,
    common,
    judge_room,
    keyfile,
    label,
    outcomes,
    truth,
    write_jsonl,
)  # fmt: skip
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.query_helpers import tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def test_statistics_match_worked_examples():
    assert cohen([("a", "a"), ("b", "b"), ("a", "b"), ("a", "a")]) == pytest.approx(0.5)
    units = [["a", "a", "a"], ["b", "b", "a"], ["a", "b", "b"]]
    assert fleiss(units) == pytest.approx(0.1)
    assert krippendorff(units) == pytest.approx(0.2)
    assert cohen([("a", "a"), ("a", "a")]) is None  # undefined, not 1


def _humans(n: int = 20, flip: set = frozenset()) -> dict:
    return {f"i{k}": {"h": ("fail" if truth(k) == "pass" else "pass") if k in flip else truth(k)}
            for k in range(n)}  # fmt: skip


def _judge(n: int = 20, flip: set = frozenset(), abstain: set = frozenset()) -> dict:
    out = {}
    for k in range(n):
        if k in abstain:
            out[f"i{k}"] = {"status": "abstain", "label": None}
        else:
            value = truth(k) if k not in flip else ("fail" if truth(k) == "pass" else "pass")
            out[f"i{k}"] = {"status": "label", "label": value}
    return out


def test_the_floor_is_the_lower_bound_and_is_reproducible():
    good = report(_judge(), _humans(), seed=3, resamples=400)
    assert good["method"] == "cohen-kappa" and good["value"] == "1.000000" and good["meets_floor"]
    assert report(_judge(), _humans(), seed=3, resamples=400) == good
    noisy = report(_judge(flip={1, 2, 4, 6}), _humans(), seed=3, resamples=400)
    assert float(noisy["value"]) > 0.5 and not noisy["meets_floor"]  # point above, bound below
    assert float(noisy["ci"][0]) < 0.6


def test_abstaining_on_hard_items_lowers_coverage_and_fails():
    hard = {0, 3, 6, 9}  # the judge would get these wrong, so it abstains on them
    got = report(_judge(abstain=hard), _humans(), seed=1, resamples=200)
    assert got["value"] == "1.000000" and got["abstained"] == ["i0", "i3", "i6", "i9"]
    assert not got["meets_floor"] and any("decided 16 of 20" in r for r in got["reasons"])


def test_constant_labels_are_undefined_and_fail_closed():
    judge = {f"i{k}": {"status": "label", "label": "pass"} for k in range(5)}
    humans = {f"i{k}": {"h": "pass"} for k in range(5)}
    got = report(judge, humans, resamples=50)
    assert got["value"] is None and not got["meets_floor"]


def test_several_reviewers_use_a_multi_rater_statistic():
    humans = {f"i{k}": {"h1": truth(k), "h2": truth(k)} for k in range(12)}
    got = report(_judge(12), humans, resamples=100)
    assert got["method"] == "fleiss-kappa" and got["human_agreement"]["value"] == "1.000000"
    humans["i0"] = {"h1": truth(0)}  # uneven rater counts
    assert report(_judge(12), humans, resamples=100)["method"] == "krippendorff-alpha"


def _label_all(capsys, room: dict, seed: str, flip: set = frozenset()) -> None:
    for k in range(20):
        value = truth(k) if k not in flip else ("fail" if truth(k) == "pass" else "pass")
        assert label(capsys, room, f"i{k}", value, seed)[0] == 0


def _judge_doc(base: Path) -> tuple[Path, str]:
    doc = _judge_provenance.build("ollama:j", "Grade {output}", rubric=None)
    path = base / "judge.json"
    path.write_bytes(json.dumps(doc).encode("utf-8"))
    return path, _judge_provenance.pin(doc)


def _validate(capsys, room: dict, seed: str, judged: Path, adversarial: Path, *extra: str):
    path, _ = _judge_doc(room["base"])
    return tine(capsys, "judge", "validate", *common(room), "--judge", path.as_posix(),
                "--judge-labels", judged.as_posix(), "--adversarial", adversarial.as_posix(),
                "--key", keyfile(room, seed), "--resamples", "300",
                "--at", "2026-12-01T10:00:00Z", *extra)  # fmt: skip


def _cases(base: Path, fooled: int = 0) -> Path:
    rows = [{"id": f"a{k}", "expected": "fail", "outcome": {"status": "label",
             "label": "pass" if k < fooled else "fail"}} for k in range(4)]  # fmt: skip
    return write_jsonl(base / "adv.jsonl", rows)


def test_agreement_cli_reads_only_signed_labels(room, capsys):
    _label_all(capsys, room, REV1)
    judged = outcomes(room["base"] / "j.jsonl", {f"i{k}": truth(k) for k in range(20)})
    code, out = tine(capsys, "judge", "agreement", *common(room), "--judge-labels",
                     judged.as_posix(), "--resamples", "300")  # fmt: skip
    assert code == 0, out
    _schemas.validate(out, "tine-cli-judge-1")
    assert out["agreement"]["meets_floor"] and out["agreement"]["counted"] == 20


def test_validation_needs_adversarial_cases_and_the_floor(room, capsys):
    _label_all(capsys, room, REV1)
    base = room["base"]
    judged = outcomes(base / "j.jsonl", {f"i{k}": truth(k) for k in range(20)})
    code, out = _validate(capsys, room, SCORER, judged, _cases(base, fooled=1))
    assert code == 1 and "judge.validation-failed" in out["error"]["message"]
    bad = outcomes(base / "bad.jsonl", {f"i{k}": "pass" for k in range(20)})
    code, out = _validate(capsys, room, SCORER, bad, _cases(base))
    assert code == 1 and "below the floor" in out["error"]["message"]
    code, out = _validate(capsys, room, OPTIMIZER, judged, _cases(base))
    assert code == 1 and "judge.validation-signer" in out["error"]["message"]
    code, out = _validate(capsys, room, REV2, judged, _cases(base))  # a reviewer is not a scorer
    assert code == 1 and "judge.validation-signer" in out["error"]["message"]
    code, out = _validate(capsys, room, SCORER, judged, _cases(base))
    assert code == 0, out
    _schemas.validate(out, "tine-cli-judge-1")
    assert out["claim"]["agreement"]["meets_floor"] and out["claim"]["adversarial"]["fooled"] == 0


def _eval_folder(base: Path, pin: str, name: str = "ev") -> Path:
    folder = base / name
    folder.mkdir()
    (folder / "judge.json").write_bytes((base / "judge.json").read_bytes())
    rows = [{"item": "i0", "scorer": "llm-judge", "scorer_version": pin}]
    write_jsonl(folder / "verdicts.jsonl", rows)
    return folder


def test_promote_gate_is_advisory_by_default_and_refuses_under_rsi(room, capsys):
    base = room["base"]
    _, pin = _judge_doc(base)
    folder = _eval_folder(base, pin)
    repo_path = room["repo"].path.parent
    run = "run:sha256:" + "e" * 64
    policy = {}
    _promote_judges.check_policy(policy)
    assert policy["judge_assurance"] == "advisory"
    held, told = _promote_judges.findings(policy, repo_path, run, None, {"evals": folder})
    assert held == [] and told[0]["code"] == "advisory:judge.unvalidated"
    rsi = {"profile": "rsi"}
    _promote_judges.check_policy(rsi)
    with pytest.raises(ValueError):
        _promote_judges.check_policy({"profile": "rsi", "judge_assurance": "advisory"})
    held, _ = _promote_judges.findings(rsi, repo_path, run, None, {"evals": folder})
    assert [r["code"] for r in held] == ["promote.judge-unvalidated"]
    (folder / "judge.json").unlink()  # deleting the judge's provenance does not skip the gate
    held, _ = _promote_judges.findings(rsi, repo_path, run, None, {"evals": folder})
    assert [r["code"] for r in held] == ["promote.judge-unvalidated"]
    _label_all(capsys, room, REV1)
    judged = outcomes(base / "j.jsonl", {f"i{k}": truth(k) for k in range(20)})
    assert _validate(capsys, room, SCORER, judged, _cases(base))[0] == 0
    good = _eval_folder(base, pin, "ev2")
    assert _promote_judges.findings(rsi, repo_path, run, None, {"evals": good}) == ([], [])
    with pytest.raises(ValueError):
        _promote_judges.check_policy({"judge_floor": "1.5"})
    other = _judge_provenance.build("ollama:j", "Grade {output} generously", rubric=None)
    (base / "judge.json").write_bytes(json.dumps(other).encode("utf-8"))
    swapped = _eval_folder(base, _judge_provenance.pin(other), "ev3")  # another judge, same model
    held, _ = _promote_judges.findings(rsi, repo_path, run, None, {"evals": swapped})
    assert [r["code"] for r in held] == ["promote.judge-unvalidated"]
