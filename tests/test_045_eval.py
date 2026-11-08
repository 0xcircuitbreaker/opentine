"""0.45: ``tine eval run|verify|compare``, datasets and ``tine-eval-verdict/1``."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import opentine.cli as cli
from opentine import _eval_judge, _eval_verdict
from opentine._eval_dataset import DatasetError, export_hf, import_hf, read_jsonl
from opentine._eval_run import read_verdicts, verify_eval
from opentine._eval_scorers import ScorerError, conforms, parse
from opentine._pyz import _evalv
from opentine.graph import Run, RunStatus, StepKind
from opentine.signing import generate_ed25519

WHEN = "2026-11-08T00:00:00Z"
pytestmark = pytest.mark.filterwarnings("ignore:.*plaintext-hex private key")


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    for name in ("OPENTINE_OUTPUT", "OPENTINE_FORMAT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    seed, public = generate_ed25519()
    (tmp_path / "k.key").write_text(seed, encoding="utf-8")
    (tmp_path / "k.pub").write_text(public, encoding="utf-8")
    return tmp_path


def _code(*argv: str) -> int:
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _json(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = _code(*argv, "--json")
    return code, json.loads(capsys.readouterr().out)


def _dataset(room: Path, count: int, *, wrong_every: int = 0) -> Path:
    path = room / "d.jsonl"
    rows = []
    for i in range(count):
        out = "nope" if wrong_every and i % wrong_every == 0 else str(i * 2)
        rows.append({"id": f"q{i:04d}", "input": f"{i}*2", "expected": str(i * 2),
                     "output": out, "run": "run:fixture"})  # fmt: skip
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def test_a_1k_item_eval_verifies_in_python_and_pyz(room, capsys):
    _dataset(room, 1000, wrong_every=10)
    code, row = _json(capsys, "eval", "run", "d.jsonl", "--scorer", "exact", "--key", "k.key",
                      "--out", "ev", "--created-at", WHEN)  # fmt: skip
    assert code == 0 and row["items"] == 1000 and row["passed"] == 900 and row["failed"] == 100
    assert row["mean_score"] == "0.9"
    code, checked = _json(capsys, "eval", "verify", "ev", "--pubkey", "k.pub")
    assert code == 0 and checked["ok"] and checked["eval"] == row["eval"]
    public = bytes.fromhex((room / "k.pub").read_text())
    report = _evalv.verify_eval(room / "ev", public)
    assert report[-1]["outcome"] == "pass" and report[-1]["passed"] == 900
    assert all(_evalv.verify(v, public)["item"] for v in read_verdicts(room / "ev")[:5])


def test_tampering_is_refused_with_a_code(room, capsys):
    _dataset(room, 3)
    assert (
        _code("eval", "run", "d.jsonl", "--scorer", "exact", "--key", "k.key", "--out", "ev") == 0
    )
    rows = read_verdicts(room / "ev")
    flipped = copy.deepcopy(rows[0])
    flipped["score"], flipped["passed"] = "0", False
    with pytest.raises(_eval_verdict.EvalVerdictError) as caught:
        _eval_verdict.verify(flipped)
    assert caught.value.code == "eval-verdict.bad-signature"
    with pytest.raises(_evalv.Refused) as refused:
        _evalv.verify(flipped)
    assert refused.value.code == "eval-verdict.bad-signature"
    other = bytes.fromhex(generate_ed25519()[1])
    with pytest.raises(_eval_verdict.EvalVerdictError) as wrong:
        _eval_verdict.verify(rows[0], public_key=other)
    assert wrong.value.code == "eval-verdict.wrong-key"
    lines = [json.dumps(flipped)] + [json.dumps(r) for r in rows[1:]]
    (room / "ev" / "verdicts.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    code, checked = _json(capsys, "eval", "verify", "ev")
    assert code != 0 and checked["failures"][0]["reason"] == "eval-verdict.bad-signature"


def test_compare_reports_regressions_and_fixes(room, capsys):
    _dataset(room, 20, wrong_every=5)
    _code("eval", "run", "d.jsonl", "--scorer", "exact", "--key", "k.key", "--out", "a",
          "--created-at", WHEN)  # fmt: skip
    rows = read_jsonl(room / "d.jsonl")
    rows[0]["output"], rows[1]["output"] = rows[0]["expected"], "wrong"
    (room / "o.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    _code("eval", "run", "d.jsonl", "--scorer", "exact", "--key", "k.key", "--out", "b",
          "--outputs", "o.jsonl", "--created-at", "2026-11-08T00:00:01Z")  # fmt: skip
    code, diff = _json(capsys, "eval", "compare", "a", "b", "--exit-code")
    assert code == 1 and diff["ok"]
    assert diff["regressed"] == ["q0001"] and diff["fixed"] == ["q0000"]
    assert diff["same"] == {"dataset": True, "scorer": True, "scorer_version": True}
    assert _code("eval", "compare", "a", "b") == 0


def test_scorers_regex_schema_python(room):
    item = {"id": "a", "input": "x", "expected": "y"}
    assert parse("regex:^ab+c$")(item, "abbbc") == (1.0, "")
    assert parse("regex:^ab+c$")(item, "ac")[0] == 0.0
    (room / "s.json").write_text(
        json.dumps(
            {
                "type": "object",
                "required": ["n"],
                "properties": {"n": {"type": "integer", "minimum": 1}},
                "additionalProperties": False,
            }
        )
    )
    schema = parse("json-schema:s.json")
    assert schema(item, '{"n": 2}')[0] == 1.0 and schema(item, '{"n": 0}')[0] == 0.0
    assert schema(item, {"n": 2, "x": 1})[0] == 0.0 and schema.version.startswith("1+sha256:")
    assert conforms(["a"], {"type": "array", "items": {"enum": ["a"]}})
    (room / "sc.py").write_text("def half(output, item):\n    return {'score': 0.5}\n")
    scorer = parse("python:sc.py:half")
    assert scorer(item, "z") == (0.5, "") and scorer.id == "python"
    (room / "bad.py").write_text("def f(output, item):\n    return 7\n")
    with pytest.raises(ScorerError):
        parse("python:bad.py:f")(item, "z")
    with pytest.raises(ScorerError):
        parse("nope")


def test_llm_judge_is_recorded_as_its_own_run(room, capsys, monkeypatch):
    class Fake:
        async def complete(self, messages, **_):
            assert "Answer to grade: 4" in messages[0]["content"]
            return {"text": "Looks right.\nSCORE: 0.75"}

    monkeypatch.setattr(_eval_judge, "_model", lambda spec: Fake())
    monkeypatch.setattr(cli, "RUNS_DIR", room / "runs")
    rows = [{"id": "j1", "input": "2+2", "expected": "4", "output": "4", "run": "run:x"}]
    (room / "d.jsonl").write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
    code, row = _json(capsys, "eval", "run", "d.jsonl", "--scorer", "llm-judge:ollama:tiny",
                      "--key", "k.key", "--out", "ev", "--threshold", "0.7")  # fmt: skip
    assert code == 0 and row["passed"] == 1 and row["mean_score"] == "0.75"
    verdict = read_verdicts(room / "ev")[0]
    assert verdict["scorer"] == "llm-judge" and verdict["judge_run"]
    judge = Run.load(next((room / "runs").glob("*.tine")))
    assert judge.id == verdict["judge_run"] and "eval-judge" in judge.tags
    assert "SCORE: 0.75" in json.dumps(judge.steps[0].outputs)
    assert _evalv.verify(verdict)["passed"] and verify_eval(room / "ev")["ok"]


def test_dataset_from_run_and_hf_round_trip(room, capsys, monkeypatch):
    monkeypatch.setattr(cli, "RUNS_DIR", room / "runs")
    run = Run(model_info="m", user_prompt="What is 2+2?")
    run.add_step(StepKind.model, {"text": "What is 2+2?"}, {"text": "4"})
    run.status = RunStatus.completed
    (room / "runs").mkdir()
    run.save(room / "runs" / f"{run.id}.tine")
    code, row = _json(capsys, "dataset", "add", "ds.jsonl", "--from-run", run.id,
                      "--expected", "4", "--id", "two")  # fmt: skip
    assert code == 0 and row["items"] == 1 and row["run"] == run.id
    item = read_jsonl(room / "ds.jsonl")[0]
    assert item == {"id": "two", "input": "What is 2+2?", "output": "4", "run": run.id,
                    "expected": "4"}  # fmt: skip
    assert _code("dataset", "add", "ds.jsonl", "--from-run", run.id, "--id", "two") != 0
    assert _code("dataset", "export", "ds.jsonl", "--format", "hf", "--out", "hf") == 0
    assert (room / "hf" / "data" / "train.jsonl").is_file()
    assert "configs:" in (room / "hf" / "README.md").read_text()
    back = import_hf(room / "hf")
    assert back[0]["id"] == "two" and back[0]["metadata"]["run"] == run.id
    assert (
        _code("eval", "run", "ds.jsonl", "--scorer", "exact", "--key", "k.key", "--out", "e") == 0
    )
    assert verify_eval(room / "e")["passed"] == 1
    code, shown = _json(capsys, "dataset", "show", "ds.jsonl")
    assert shown["items"] == 1 and shown["digest"].startswith("sha256:")


def test_hf_import_maps_columns_and_rejects_parquet_only(room):
    (room / "h" / "data").mkdir(parents=True)
    rows = [{"question": "q", "answer": "a", "uid": "u1", "src": "x"}]
    (room / "h" / "data" / "test-00000.jsonl").write_text(json.dumps(rows[0]) + "\n")
    items = import_hf(room / "h", split="test", id_field="uid", input_field="question",
                      expected_field="answer")  # fmt: skip
    assert items == [{"id": "u1", "input": "q", "expected": "a", "metadata": {"src": "x"}}]
    with pytest.raises(DatasetError, match="Parquet"):
        import_hf(room / "h", split="train")
    export_hf(room / "o", items)
    assert json.loads((room / "o" / "dataset_info.json").read_text())["splits"] == {"train": 1}


def test_items_without_a_run_are_refused(room):
    (room / "d.jsonl").write_text(json.dumps({"id": "a", "input": "x", "output": "y"}) + "\n")
    assert _code("eval", "run", "d.jsonl", "--scorer", "exact", "--key", "k.key", "--out", "e") != 0
    assert _code("eval", "run", "d.jsonl", "--scorer", "exact", "--key", "k.key", "--out", "e",
                 "--run", "run:given") == 0  # fmt: skip


def test_a_bad_regex_scorer_is_a_scorer_error():
    with pytest.raises(ScorerError, match="regex scorer pattern"):
        parse("regex:(unclosed")
