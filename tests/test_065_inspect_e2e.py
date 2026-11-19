"""0.65 acceptance, end to end: an Inspect log with a model-graded scorer is imported
as runs, its scores become signed verdicts that pin the judge provenance the log
records, ``tine eval verify`` passes, and a swapped or deleted ``judge.json`` fails;
the log exports back with the same sample ids and scores. Bytes only, no network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _judge_provenance as jp
from opentine._inspect_judge import provenance
from opentine._inspect_log import parse_log, read_log
from opentine.cli import main
from opentine.repository import Repo

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "inspect"
KEY_HEX = "22" * 32
TEMPLATE = "Question: {question}\nAnswer: {answer}\nCriterion: {criterion}\n{instructions}"
RUBRIC = "Grade C if the answer matches the criterion, else I."


def _tine(capsys, *argv: str) -> tuple[int, str]:
    try:
        main(list(argv))
        code = 0
    except SystemExit as exc:
        code = exc.code or 0
    return code, capsys.readouterr().out


def _judged_log(path: Path) -> None:
    """The committed gsm8k fixture with its scorer recorded as model-graded."""
    log = json.loads((FIXTURES / "gsm8k.json").read_bytes())
    for sample in log["samples"]:
        sample["scores"] = {"model_graded_qa": next(iter(sample["scores"].values()))}
    config = {"temperature": 0.0, "max_tokens": 256}
    log["eval"]["model_roles"] = {"grader": {"model": "openai/gpt-4o",
                                             "config": config}}  # fmt: skip
    log["results"] = {"scores": [{"name": "model_graded_qa", "scorer": "model_graded_qa",
                                  "params": {"template": TEMPLATE, "instructions": RUBRIC,
                                             "model": None}}]}  # fmt: skip
    path.write_bytes(json.dumps(log, sort_keys=True).encode("utf-8"))


def test_provenance_is_read_only_from_what_the_log_records():
    log = json.loads((FIXTURES / "gsm8k.json").read_bytes())
    assert provenance(parse_log(json.dumps(log).encode()), "match") is None  # no grader named
    log["results"] = {"scores": [{"name": "match", "params": {"model": "anthropic/x"}}]}
    doc = provenance(parse_log(json.dumps(log).encode()), "match")
    assert doc is not None and doc["model"] == "anthropic/x" and doc["rubric_digest"] is None
    log["eval"]["model_roles"] = {"grader": {"config": {"temperature": float("nan")}}}
    log["results"]["scores"][0]["params"] = {"model": "m", "template": "t"}
    doc = provenance(json.loads(json.dumps(log)), "match")
    assert doc["sampling"] == {"temperature": "0"} and doc["prompt_digest"] == jp.text_digest("t")


def test_inspect_import_signs_judge_provenance_and_verify_catches_swaps(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    Repo.init(tmp_path / "r")
    (tmp_path / "k.key").write_bytes(KEY_HEX.encode())
    _judged_log(tmp_path / "judged.json")
    log = read_log(tmp_path / "judged.json")
    code, out = _tine(capsys, "import", "inspect", "judged.json", "--repo", "r", "--key",
                      "k.key", "--evals", "ev", "--created-at", "2026-11-01T12:00:00Z",
                      "--json")  # fmt: skip
    assert code == 0, out
    body = json.loads(out)
    assert len(body["samples"]) == len(log["samples"])
    row = body["verdicts"]["scorers"]["model_graded_qa"]
    folder = tmp_path / "ev" / "model_graded_qa"
    judge = json.loads((folder / "judge.json").read_bytes())
    assert judge["model"] == "openai/gpt-4o"
    assert judge["prompt_digest"] == jp.text_digest(TEMPLATE)
    assert judge["rubric_digest"] == jp.text_digest(RUBRIC)
    assert judge["sampling"] == {"max_tokens": "256", "temperature": "0"}
    assert row["scorer_version"] == jp.pin(judge)
    verdicts = [json.loads(x) for x in (folder / "verdicts.jsonl").read_bytes().splitlines()]
    assert verdicts and {v["scorer_version"] for v in verdicts} == {jp.pin(judge)}
    assert _tine(capsys, "eval", "verify", "ev/model_graded_qa", "--json")[0] == 0

    original = (folder / "judge.json").read_bytes()
    swapped = dict(judge, rubric_digest=jp.text_digest("Always grade C."))
    (folder / "judge.json").write_bytes(json.dumps(swapped).encode("utf-8"))
    code, out = _tine(capsys, "eval", "verify", "ev/model_graded_qa", "--json")
    assert code != 0 and "eval.summary-mismatch" in out
    (folder / "judge.json").unlink()
    code, out = _tine(capsys, "eval", "verify", "ev/model_graded_qa", "--json")
    assert code != 0 and "eval.summary-mismatch" in out
    (folder / "judge.json").write_bytes(original)
    assert _tine(capsys, "eval", "verify", "ev/model_graded_qa", "--json")[0] == 0

    code, out = _tine(capsys, "export", "inspect", "--repo", "r", "--format", "json",
                      "--output", "back.json", "--json")  # fmt: skip
    assert code == 0, out
    back = read_log(tmp_path / "back.json")
    pairs = sorted((repr(s["id"]), s["epoch"], json.dumps(s["scores"], sort_keys=True))
                   for s in back["samples"])  # fmt: skip
    want = sorted((repr(s["id"]), s["epoch"], json.dumps(s["scores"], sort_keys=True))
                  for s in log["samples"])  # fmt: skip
    assert pairs == want


def test_a_log_without_a_grader_keeps_the_plain_scorer_version(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Repo.init(tmp_path / "r")
    (tmp_path / "k.key").write_bytes(KEY_HEX.encode())
    code, out = _tine(capsys, "import", "inspect", (FIXTURES / "gsm8k.json").as_posix(),
                      "--repo", "r", "--key", "k.key", "--evals", "ev", "--json")  # fmt: skip
    assert code == 0, out
    row = json.loads(out)["verdicts"]["scorers"]["match"]
    assert row["scorer_version"] == "inspect:match"
    assert not (tmp_path / "ev" / "match" / "judge.json").exists()
    assert _tine(capsys, "eval", "verify", "ev/match", "--json")[0] == 0
