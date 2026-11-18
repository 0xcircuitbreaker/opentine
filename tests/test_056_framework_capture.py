"""Framework capture over OTLP: span -> run -> export keeps every attribute.

One OTLP/JSON fixture per framework recipe in docs/CAPTURE.md (Claude Agent
SDK, OpenAI Agents SDK, LangGraph, Pydantic AI). Each is imported through the
CLI into a saved run, loaded back and exported; every attribute the framework
emitted must come out with the same value, the GenAI mapping must be readable,
and the seeded secret in a captured prompt must not reach the run.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from opentine import Run, cli
from opentine._artifact_io import read_artifact_json
from opentine.trace import otel_genai_events, to_otel_genai
from opentine.trace._import_helpers import otel_spans
from opentine.trace._otel_aliases import genai_aliases
from opentine.trace._otel_values import attributes as decoded

FIXTURES = Path(__file__).parent / "fixtures" / "otel_frameworks"
FRAMEWORKS = ("claude_agent_sdk", "openai_agents", "langgraph", "pydantic_ai")
SECRET = "AKIAIOSFODNN7EXAMPLE"

#: Keys import consumes into typed event fields and export writes back in an
#: equivalent (not byte-identical) spelling; their content is checked separately.
CONSUMED = {"gen_ai.prompt", "gen_ai.input.messages", "gen_ai.output.messages"}


def _document(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_bytes())


def _import(tmp_path: Path, name: str) -> Run:
    output = tmp_path / f"{name}.tine"
    try:
        cli.main(
            [
                "import",
                str(FIXTURES / f"{name}.json"),
                "--format",
                "otel-json",
                "--save",
                str(output),
            ]
        )
    except SystemExit as exc:
        assert not exc.code
    return Run.load(output)


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_every_framework_attribute_survives_span_run_export(tmp_path, monkeypatch, name):
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = _import(tmp_path, name)
    exported = [decoded(span) for span in to_otel_genai(run)]
    original = [decoded(span) for span in otel_spans(_document(name))]
    assert len(exported) == len(original)
    for source, out in zip(original, exported, strict=True):
        for key, value in source.items():
            if key in CONSUMED or key.startswith(("llm.input_messages.", "llm.output_messages.")):
                continue
            assert key in out, f"{name}: {key} dropped"
            if SECRET not in json.dumps(value):
                assert out[key] == value, f"{name}: {key} changed"


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_framework_spans_map_onto_genai_kinds_models_and_usage(name):
    events = otel_genai_events(_document(name))
    kinds = [event.kind for event in events]
    assert kinds[1:] == ["model", "tool"]
    model = events[1]
    assert model.model and model.provider
    assert model.usage.get("output", 0) > 0
    assert model.inputs, "captured prompt imported empty"


def test_openinference_inclusive_counts_split_into_exclusive_buckets():
    model = otel_genai_events(_document("openai_agents"))[1]
    assert model.usage["cache_read"] == 100
    assert model.usage["input"] == 200
    assert model.usage["output"] == 50


def test_aliases_never_overwrite_or_remove_a_source_key():
    source = {"llm.model_name": "a", "gen_ai.request.model": "b", "openinference.span.kind": "LLM"}
    mapped = genai_aliases(source)
    assert mapped["gen_ai.request.model"] == "b"
    assert mapped["gen_ai.operation.name"] == "chat"
    assert all(mapped[key] == value for key, value in source.items())


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_seeded_secret_in_a_captured_prompt_never_reaches_the_run(tmp_path, monkeypatch, name):
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    _import(tmp_path, name)
    artifact = read_artifact_json(tmp_path / f"{name}.tine")
    stored = [base64.b64decode(item["data"]) for item in artifact["objects"].values()
              if item.get("encoding") == "raw"]  # fmt: skip
    assert any(b"[REDACTED]" in blob for blob in stored)
    assert all(SECRET.encode() not in blob for blob in stored)
    assert SECRET not in json.dumps(artifact)


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_the_exported_run_re_imports_to_the_same_kinds_models_and_usage(
    tmp_path, monkeypatch, name
):
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    again = otel_genai_events(to_otel_genai(_import(tmp_path, name)))
    first = otel_genai_events(_document(name))
    assert [(e.kind, e.model, e.provider, dict(e.usage)) for e in again] == [
        (e.kind, e.model, e.provider, dict(e.usage)) for e in first
    ]
