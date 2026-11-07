"""0.42 ``tine explain RUN``: deterministic summary, annotation, labelled narrative."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _explain, cli
from opentine.graph import Run, StepKind
from opentine.repository import Repo
from opentine.repository._annotations import load_run_annotation


def _run() -> Run:
    run = Run(id="exrun0001", model_info="m-1", user_prompt="fix the \x1b[31mbug")
    run.add_step(StepKind.model, {"text": "fix"}, {"text": "ok"}, model_info="m-1",
                 usage={"input": 10, "output": 5})  # fmt: skip
    run.add_step(
        StepKind.tool,
        {"name": "write_file", "arguments": {"path": "a.py", "content": "x = 1\n"}},
        {"result": "ok"},
        tool_info={"name": "write_file"},
    )
    run.add_step(StepKind.error, {"text": "boom"}, error={"message": "it broke", "type": "E"})
    run.add_step(StepKind.done, {}, {"text": "done fixing"})
    return run


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Repo:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv(_explain.NARRATIVE_ENV, raising=False)
    store = Repo.init(tmp_path)
    store.put_run(_run(), ref="heads/main")
    return store


def _invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_summary_facts_and_absent_unknowns() -> None:
    summary = _explain.summarize(_run())
    assert summary["asked"] == "fix the [31mbug"  # control bytes never reach a terminal
    assert summary["files_written"] == ["a.py"]
    assert summary["tools"] == {"write_file": 1}
    assert summary["outcome"] == {"status": "running", "final_text": "done fixing"}
    assert summary["errors"][0]["message"] == "it broke"
    assert summary["token_usage"] == {"input": 10, "output": 5}
    assert "cost_usd" not in summary  # nothing recorded: absent, never 0
    empty = _explain.summarize(Run(id="empty0001"))
    assert "token_usage" not in empty and empty["asked"] == ""


def test_same_input_gives_byte_identical_output(repo, capsys) -> None:
    first = _invoke(capsys, "explain", "main", "--json")
    second = _invoke(capsys, "explain", "main", "--json")
    assert first == second and first[0] == 0
    text = _invoke(capsys, "explain", "main")
    assert text == _invoke(capsys, "explain", "main")
    assert "Files written: a.py" in text[1]


def test_json_contract_and_annotation_is_stored_once(repo, capsys) -> None:
    code, out, _ = _invoke(capsys, "explain", "main", "--json")
    payload = json.loads(out)
    assert code == 0 and payload["command"] == "explain"
    assert set(payload) == {"command", "run", "digest", "summary", "stored", "annotation",
                            "narrative"}  # fmt: skip
    assert payload["stored"] is True and payload["narrative"] is None
    assert payload["digest"] == _explain.digest(payload["summary"])
    metadata, _ = load_run_annotation(repo, payload["run"])
    assert metadata[_explain.ANNOTATION_KEY] == payload["summary"]
    again = json.loads(_invoke(capsys, "explain", "main", "--json")[1])
    assert again["annotation"] == payload["annotation"]  # deduplicated, not re-written


def test_no_store_writes_nothing(repo, capsys) -> None:
    payload = json.loads(_invoke(capsys, "explain", "main", "--no-store", "--json")[1])
    assert payload["stored"] is False
    assert _explain.ANNOTATION_KEY not in load_run_annotation(repo, payload["run"])[0]


def test_narrative_refuses_without_a_local_model(repo, capsys, monkeypatch) -> None:
    code, out, err = _invoke(capsys, "explain", "main", "--narrative")
    assert code == 2 and out == "" and _explain.NARRATIVE_ENV in err
    monkeypatch.setenv(_explain.NARRATIVE_ENV, "anthropic:claude")
    code, _, err = _invoke(capsys, "explain", "main", "--narrative")
    assert code == 2 and "not a local provider" in err


def test_narrative_is_labelled_model_generated(repo, capsys, monkeypatch) -> None:
    class Fake:
        async def complete(self, messages, **_):
            assert "exrun0001" in messages[0]["content"]
            return {"text": "The agent wrote a.py."}

    monkeypatch.setenv(_explain.NARRATIVE_ENV, "ollama:tiny")
    monkeypatch.setattr(_explain, "_model", lambda spec: Fake())
    payload = json.loads(_invoke(capsys, "explain", "main", "--narrative", "--json")[1])
    story = payload["narrative"]
    assert story["generated_by"] == "model" and story["label"] == _explain.NARRATIVE_LABEL
    assert story["summary_digest"] == payload["digest"] and story["model"] == "ollama:tiny"
    stored = load_run_annotation(repo, payload["run"])[0][_explain.NARRATIVE_KEY]
    assert stored == story
    # The deterministic summary is untouched by the narrative.
    assert (
        load_run_annotation(repo, payload["run"])[0][_explain.ANNOTATION_KEY] == payload["summary"]
    )


def test_legacy_run_is_explained_not_stored(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    path = Path(tmp_path, "r.tine")
    _run().save(path)
    payload = json.loads(_invoke(capsys, "explain", str(path), "--json")[1])
    assert payload["stored"] is False and payload["summary"]["run"] == "exrun0001"
