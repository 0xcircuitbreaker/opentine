"""0.46 vendor I/O: Langfuse, Phoenix, Braintrust and LangSmith files, offline.

Each vendor's export is the JSON body its public ingestion API takes; each
import reads that body (or the vendor's own export shape) back through the
OTLP importer. Scores ride as ``gen_ai.evaluation.result`` and survive the
round trip in every direction.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _vendor_io, cli
from opentine.core import Run

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "fixtures" / "golden_v2.tine"
T0 = 1_762_600_000_000_000_000
EVAL = {"name": "accuracy", "score": 0.75, "label": None, "explanation": None}
LABEL = {"name": "verdict", "score": None, "label": "pass", "explanation": "all tests ran"}


def _spans() -> list[dict]:
    base = {"trace": "trace-1", "tokens_in": None, "tokens_out": None, "error": None,
            "model": None, "evals": []}  # fmt: skip
    return [
        {**base, "span": "root", "parent": None, "name": "agent", "kind": "step",
         "start": T0, "end": T0 + 9_000_000, "input": "fix the bug", "output": "fixed"},
        {**base, "span": "llm-1", "parent": "root", "name": "chat", "kind": "model",
         "start": T0 + 1_000_000, "end": T0 + 2_000_000, "input": {"messages": ["hi"]},
         "output": {"text": "ok"}, "model": "gpt-x", "tokens_in": 12, "tokens_out": 3,
         "evals": [dict(EVAL), dict(LABEL)]},
        {**base, "span": "tool-1", "parent": "llm-1", "name": "bash", "kind": "tool",
         "start": T0 + 3_000_000, "end": T0 + 4_000_000, "input": {"cmd": "ls"},
         "output": "a.py", "error": "exit 1"},
    ]  # fmt: skip


@pytest.mark.parametrize("fmt", _vendor_io.VENDOR_FORMATS)
def test_every_vendor_file_round_trips_spans_and_scores(fmt):
    module = _vendor_io._module(fmt)
    document = json.loads(json.dumps(module.export(_spans())))
    back = {span["name"]: span for span in module.parse(document)}
    assert set(back) == {"agent", "chat", "bash"}
    assert back["chat"]["kind"] == "model" and back["bash"]["kind"] == "tool"
    assert back["chat"]["model"] == "gpt-x"
    assert (back["chat"]["tokens_in"], back["chat"]["tokens_out"]) == (12, 3)
    assert back["bash"]["error"] == "exit 1" and back["agent"]["error"] is None
    assert back["chat"]["start"] == T0 + 1_000_000 and back["chat"]["end"] == T0 + 2_000_000
    assert sorted(back["chat"]["evals"], key=lambda e: e["name"]) == [EVAL, LABEL]
    assert back["bash"]["output"] == "a.py" or back["bash"]["output"] == {"value": "a.py"}
    parents = {span["name"]: span["parent"] for span in back.values()}
    assert parents["agent"] is None
    assert parents["chat"] == back["agent"]["span"] and parents["bash"] == back["chat"]["span"]


@pytest.mark.parametrize("fmt", _vendor_io.VENDOR_FORMATS)
def test_imports_go_through_the_otlp_importer_with_scores_kept(fmt):
    text = json.dumps(_vendor_io._module(fmt).export(_spans()))
    events = _vendor_io.import_events(fmt, text)
    assert [event.kind for event in events] == ["model", "model", "tool"]
    scored = [e for e in events if _vendor_io.EVAL_ATTRIBUTE in e.attributes]
    assert len(scored) == 1
    evals = json.loads(scored[0].attributes[_vendor_io.EVAL_ATTRIBUTE])
    assert sorted(evals, key=lambda e: e["name"]) == [EVAL, LABEL]


def test_the_otlp_bridge_writes_gen_ai_evaluation_result_events():
    document = _vendor_io.to_otlp(_spans())
    spans = document["resourceSpans"][0]["scopeSpans"][0]["spans"]
    chat = next(span for span in spans if span["name"] == "chat")
    names = [event["name"] for event in chat["events"]]
    assert names == ["gen_ai.evaluation.result"] * 2
    keys = {a["key"] for e in chat["events"] for a in e["attributes"]}
    assert {"gen_ai.evaluation.name", "gen_ai.evaluation.score.value",
            "gen_ai.evaluation.score.label", "gen_ai.evaluation.explanation"} <= keys  # fmt: skip


def test_vendor_shapes_match_their_ingestion_apis():
    spans = _spans()
    langfuse = _vendor_io._module("langfuse").export(spans)["batch"]
    assert {e["type"] for e in langfuse} == {"trace-create", "span-create", "generation-create",
                                             "score-create"}  # fmt: skip
    gen = next(e["body"] for e in langfuse if e["type"] == "generation-create")
    assert gen["usageDetails"] == {"input": 12, "output": 3} and gen["parentObservationId"]
    categorical = [e["body"] for e in langfuse if e["type"] == "score-create"]
    assert {s["dataType"] for s in categorical} == {"NUMERIC", "CATEGORICAL"}
    phoenix = _vendor_io._module("phoenix").export(spans)
    llm = next(s for s in phoenix["data"] if s["span_kind"] == "LLM")
    assert llm["attributes"]["llm.token_count.prompt"] == 12
    assert phoenix["span_annotations"][0]["annotator_kind"] == "CODE"
    rows = _vendor_io._module("braintrust").export(spans)["events"]
    chat = next(r for r in rows if r["span_attributes"]["type"] == "llm")
    assert chat["scores"] == {"accuracy": 0.75}  # a label is not a Braintrust score
    assert chat["metadata"]["opentine.evaluations"] == [LABEL]
    smith = _vendor_io._module("langsmith").export(spans)
    runs = {r["name"]: r for r in smith["post"]}
    assert runs["bash"]["dotted_order"].startswith(runs["agent"]["dotted_order"] + ".")
    assert runs["bash"]["dotted_order"].count(".") == 2
    assert runs["chat"]["outputs"]["usage_metadata"] == {"input_tokens": 12, "output_tokens": 3}
    assert {f["key"] for f in smith["feedback"]} == {"accuracy", "verdict"}


def test_vendor_native_exports_import(tmp_path):
    langfuse_trace = {
        "id": "t",
        "observations": [
            {
                "id": "o1",
                "type": "GENERATION",
                "name": "chat",
                "model": "m",
                "startTime": "2025-11-08T10:00:00.000Z",
                "endTime": "2025-11-08T10:00:01.000Z",
                "usageDetails": {"input": 5, "output": 2},
                "input": "q",
                "output": "a",
            }
        ],
        "scores": [{"name": "helpful", "value": 1, "observationId": "o1", "traceId": "t"}],
    }
    spans = _vendor_io.parse_document("langfuse", json.dumps({"data": [langfuse_trace]}))
    assert spans[0]["evals"] == [{"name": "helpful", "score": 1, "label": None,
                                  "explanation": None}]  # fmt: skip
    nested = {
        "name": "llm",
        "context": {"trace_id": "a" * 32, "span_id": "b" * 16},
        "span_kind": "LLM",
        "start_time": "2025-11-08T10:00:00+00:00",
        "attributes": {"input": {"value": "hi"}, "llm": {"model_name": "m"}},
    }
    phoenix = _vendor_io.parse_document("phoenix", json.dumps(nested) + "\n")
    assert phoenix[0]["model"] == "m" and phoenix[0]["input"] == "hi"
    rows = "\n".join(
        json.dumps(r)
        for r in [
            {
                "id": "1",
                "span_id": "1",
                "root_span_id": "1",
                "input": "x",
                "span_attributes": {"name": "task", "type": "task"},
                "scores": {"ok": 1},
            }
        ]
    )
    assert _vendor_io.parse_document("braintrust", rows)[0]["evals"][0]["score"] == 1
    with pytest.raises(ValueError):
        _vendor_io.parse_document("langsmith", "[]")


def _tine(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


@pytest.mark.parametrize("fmt", _vendor_io.VENDOR_FORMATS)
def test_tine_export_and_import_a_vendor_file(fmt, tmp_path, capsys):
    out = tmp_path / f"{fmt}.json"
    code, _ = _tine(capsys, "export", str(GOLDEN), "--format", fmt, "--output", str(out))
    assert code == 0 and out.exists()
    document = json.loads(out.read_text("utf-8"))
    assert set(document) == set(_vendor_io.export_document(fmt, Run.load(GOLDEN)))
    saved = tmp_path / "back.tine"
    code, _ = _tine(capsys, "import", str(out), "--format", fmt, "--save", str(saved))
    assert code == 0
    assert [s.kind.value for s in Run.load(saved).steps] == ["model", "tool", "model"]


def test_a_vendor_export_is_never_pushed(tmp_path, capsys):
    code, _ = _tine(capsys, "export", str(GOLDEN), "--format", "langsmith", "--endpoint",
                    "http://127.0.0.1:9/")  # fmt: skip
    assert code == 1


@pytest.mark.parametrize(
    ("value", "expected"),
    [(1.7e9, 1_700_000_000_000_000_000), (1_700_000_000_000, 1_700_000_000_000_000_000),
     (1_700_000_000_000_000, 1_700_000_000_000_000_000), (1_700_000_000_123_456_789,
     1_700_000_000_123_456_789), (float("inf"), 0), (float("nan"), 0), (-1, 0), (10**30, 0)],
)  # fmt: skip
def test_epoch_numbers_are_read_by_magnitude(value, expected):
    from opentine._vendor_io import nanos

    assert nanos(value) == expected


@pytest.mark.parametrize("fmt", ["langfuse", "phoenix", "braintrust", "langsmith"])
@pytest.mark.parametrize(
    "document",
    [{"batch": 3, "data": 1.5, "spans": True, "runs": 1, "context": 2, "scores": [[1]]},
     [{"id": "a", "start_time": float("inf"), "startTime": 1e300, "metrics": {"start": 1e300}}],
     [{"id": ["x"], "span_id": {"a": 1}, "trace_id": [], "events": 1, "attributes": 1}]],
)  # fmt: skip
def test_a_malformed_vendor_file_is_a_value_error_not_a_crash(fmt, document):
    from opentine._vendor_io import import_events

    try:
        import_events(fmt, json.dumps(document))
    except ValueError:
        pass
