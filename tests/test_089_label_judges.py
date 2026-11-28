"""0.89: label judges return a label, a probability or an explicit abstain; never a silent 0."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import opentine.cli as cli
from opentine import _eval_judge, _schemas
from opentine._judge_label import check_labels, parse
from tests.judge_helpers import fake_models, judge_room, write_jsonl  # noqa: F401
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.query_helpers import tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
LABELS = ["pass", "fail"]


@pytest.mark.parametrize(("reply", "status", "label", "prob"), [
    ("ok\nLABEL: pass\nPROBABILITY: 0.90", "label", "pass", "0.9"),
    ("LABEL: fail", "label", "fail", None),
    ("not sure\nLABEL: ABSTAIN", "abstain", None, None),
    ("ABSTAIN", "abstain", None, None),
    ("the answer looks fine", "error", None, None),          # no label line: not a 0
    ("LABEL: maybe", "error", None, None),                    # outside the set
    ("LABEL: pass\nLABEL: fail", "error", None, None),        # two outcomes
    ("LABEL: pass\nABSTAIN", "error", None, None),            # label and abstain
    ("LABEL: pass\nPROBABILITY: 1.5", "error", None, None),   # probability outside 0..1
    ("LABEL: pass\nPROBABILITY: nan", "error", None, None),
    ("LABEL: pass\nPROBABILITY: 0.2\nPROBABILITY: 0.9", "error", None, None),
])  # fmt: skip
def test_parse_has_three_outcomes_and_no_default_label(reply, status, label, prob):
    got = parse(reply, LABELS)
    assert (got["status"], got["label"], got["probability"]) == (status, label, prob)


def test_label_sets_are_checked():
    with pytest.raises(ValueError):
        check_labels(["pass"])
    with pytest.raises(ValueError):
        check_labels(["pass", "ABSTAIN"])
    with pytest.raises(ValueError):
        check_labels(["pass", "pass"])


def test_the_numeric_judge_errors_instead_of_scoring_zero():
    with pytest.raises(_eval_judge.JudgeParseError):
        _eval_judge.judge_score("looks fine to me")
    with pytest.raises(_eval_judge.JudgeParseError):
        _eval_judge.judge_score("SCORE: 1.5")
    with pytest.raises(_eval_judge.JudgeParseError):
        _eval_judge.judge_score("SCORE: 0.2\nSCORE: 0.9")
    assert _eval_judge.judge_score("reason\nSCORE: 0.75") == 0.75


def test_an_unparseable_judge_reply_is_errored_not_scored(monkeypatch, tmp_path: Path):
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, (tmp_path / name.lower()).as_posix())
    monkeypatch.chdir(tmp_path)
    from opentine.signing import generate_ed25519

    seed, _ = generate_ed25519()
    (tmp_path / "k.key").write_bytes(seed.encode("utf-8"))
    rows = [{"id": f"i{n}", "input": "2+2", "expected": "4", "output": str(n), "run": "run:x"}
            for n in range(3)]  # fmt: skip
    write_jsonl(tmp_path / "d.jsonl", rows)
    replies = {"i0": "SCORE: 1", "i1": "I refuse to grade", "i2": "SCORE: 0"}

    class Fake:
        async def complete(self, messages, **_):
            item = next(k for k in replies if f"Answer to grade: {k[1:]}\n" in messages[0]
                        ["content"] + "\n")  # fmt: skip
            return {"text": replies[item]}

    monkeypatch.setattr(_eval_judge, "_model", lambda spec: Fake())
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / "runs")
    try:
        cli.main(["eval", "run", "d.jsonl", "--scorer", "llm-judge:ollama:tiny", "--key",
                  "k.key", "--out", "ev", "--continue-on-error"])  # fmt: skip
    except SystemExit as exc:
        assert not exc.code
    cov = json.loads((tmp_path / "ev" / "coverage.json").read_bytes())["claim"]
    assert cov["errored"] == ["i1"] and cov["scored"] == 2
    verdicts = [
        json.loads(x) for x in (tmp_path / "ev" / "verdicts.jsonl").read_bytes().splitlines()
    ]
    assert sorted(v["item"] for v in verdicts) == ["i0", "i2"]
    assert len(list((tmp_path / "runs").glob("*.tine"))) == 3  # the failed judgement is kept


def test_classify_keeps_abstains_and_errors_apart(room, monkeypatch, capsys):
    def reply(text: str) -> str:
        n = int(text.split("Answer to label: answer ")[1].split("\n")[0])
        return ["LABEL: pass\nPROBABILITY: 0.8", "LABEL: ABSTAIN", "garbage"][n % 3]

    fake_models(monkeypatch, {"ollama:a": reply})
    base = room["base"]
    code, out = tine(capsys, "judge", "classify", "--judge", "ollama:a", "--labels", "pass,fail",
                     "--items", (base / "items.jsonl").as_posix(), "--runs-dir",
                     (base / "runs").as_posix(), "--out",
                     (base / "o.jsonl").as_posix())  # fmt: skip
    assert code == 0, out
    _schemas.validate(out, "tine-cli-judge-1")
    assert out["counts"] == {"label": 7, "abstain": 7, "error": 6}
    by = {r["item"]: r["outcome"] for r in out["rows"]}
    assert by["i0"]["label"] == "pass" and by["i1"]["status"] == "abstain"
    assert by["i2"]["status"] == "error" and by["i2"]["label"] is None
    written = [json.loads(x) for x in (base / "o.jsonl").read_bytes().splitlines()]
    assert [r["item"] for r in written] == [r["item"] for r in out["rows"]]
