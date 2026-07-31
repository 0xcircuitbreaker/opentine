"""OpenTelemetry GenAI export: round trip against the importer, and native runs."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from opentine import Run, StepKind
from opentine.repository import Repo
from opentine.trace import (
    Recorder,
    TraceEvent,
    native_events,
    otel_genai_events,
    to_otel_genai,
    to_otel_genai_document,
)
from opentine.trace import _genai_semconv as semconv
from opentine.trace._otel_values import attributes as decoded_attributes
from opentine.trace._otel_values import encode_any_value

COMPAT = Path(__file__).parent / "fixtures" / "compat"

# Representative OTLP/JSON as an SDK emits it: camelCase keys, typed AnyValue
# attributes, string nanosecond timestamps, a parent, and a link.
SPANS = [
    {
        "name": "chat",
        "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
        "spanId": "00f067aa0ba902b7",
        "startTimeUnixNano": "2000000000",
        "endTimeUnixNano": "3500000000",
        "attributes": [
            {"key": semconv.OPERATION_NAME, "value": {"stringValue": "chat"}},
            {"key": semconv.REQUEST_MODEL, "value": {"stringValue": "gpt-5.6"}},
            {"key": semconv.RESPONSE_MODEL, "value": {"stringValue": "gpt-5.6-2026-04-01"}},
            {
                "key": semconv.PROMPT,
                "value": {
                    "arrayValue": {
                        "values": [
                            {
                                "kvlistValue": {
                                    "values": [
                                        {"key": "role", "value": {"stringValue": "user"}},
                                        {"key": "content", "value": {"stringValue": "hello"}},
                                    ]
                                }
                            }
                        ]
                    }
                },
            },
            {"key": semconv.COMPLETION, "value": {"stringValue": "hi"}},
            {"key": semconv.INPUT_TOKENS, "value": {"intValue": "120"}},
            {"key": semconv.OUTPUT_TOKENS, "value": {"intValue": "45"}},
            {"key": "server.address", "value": {"stringValue": "api.example.test"}},
        ],
    },
    {
        "name": "execute_tool",
        "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
        "spanId": "00f067aa0ba902b8",
        "parentSpanId": "00f067aa0ba902b7",
        "startTimeUnixNano": "3500000000",
        "endTimeUnixNano": "3750000000",
        "links": [
            {"traceId": "4bf92f3577b34da6a3ce929d0e0e4736", "spanId": "00f067aa0ba902b7"},
            {"spanId": "00f067aa0ba902b9"},
        ],
        "attributes": {
            semconv.OPERATION_NAME: "execute_tool",
            semconv.REQUEST_MODEL: "gpt-5.6",
            "stream": False,
        },
    },
]


def _by_key(span: dict) -> dict:
    return decoded_attributes(span)


def test_otel_genai_export_round_trips_every_field_the_importer_reads():
    events = otel_genai_events(SPANS)
    spans = to_otel_genai(events)

    assert [span["traceId"] for span in spans] == [span["traceId"] for span in SPANS]
    assert [span["spanId"] for span in spans] == [span["spanId"] for span in SPANS]
    assert "parentSpanId" not in spans[0]
    assert spans[1]["parentSpanId"] == "00f067aa0ba902b7"
    assert spans[0]["startTimeUnixNano"] == "2000000000"
    assert spans[0]["endTimeUnixNano"] == "3500000000"
    assert spans[1]["endTimeUnixNano"] == "3750000000"
    # causal_span_ids came from links, and go back out as links.
    assert [link["spanId"] for link in spans[1]["links"]] == [
        "00f067aa0ba902b7",
        "00f067aa0ba902b9",
    ]

    first, second = _by_key(spans[0]), _by_key(spans[1])
    assert first[semconv.OPERATION_NAME] == "chat"
    assert first[semconv.REQUEST_MODEL] == "gpt-5.6"
    assert first[semconv.RESPONSE_MODEL] == "gpt-5.6-2026-04-01"
    assert first[semconv.PROMPT] == [{"role": "user", "content": "hello"}]
    assert first[semconv.COMPLETION] == "hi"
    assert first[semconv.INPUT_TOKENS] == 120
    assert first[semconv.OUTPUT_TOKENS] == 45
    assert first["server.address"] == "api.example.test"
    assert second[semconv.OPERATION_NAME] == "execute_tool"
    assert second["stream"] is False
    # A span that reported no usage does not gain invented zero counters.
    assert semconv.INPUT_TOKENS not in second

    # The strong statement: re-importing the exported spans yields the very
    # same events, so nothing the importer reads was lost or invented.
    assert otel_genai_events(spans) == events
    assert to_otel_genai(otel_genai_events(spans)) == spans


def test_exported_spans_carry_a_client_span_kind_and_error_status():
    spans = to_otel_genai(
        [
            TraceEvent("error", 1.0, "t", "s", actor="chat", outputs={"message": "boom"}),
            TraceEvent("model", 1.0, "t", "s2", actor="chat"),
        ]
    )
    assert spans[0]["kind"] == "SPAN_KIND_CLIENT"
    assert spans[0]["status"] == {"code": "STATUS_CODE_ERROR"}
    assert "status" not in spans[1]
    # "chat" alone would import back as a model event, so the kind is repaired.
    assert _by_key(spans[0])["opentine.trace.kind"] == "error"
    assert otel_genai_events(spans)[0].outputs == {"message": "boom"}


def test_native_run_exports_expected_gen_ai_attributes_usage_and_timings():
    run = Run(id="native-run", model_info="kimi-k2.6")
    step = run.add_step(
        StepKind.model,
        {"prompt": "hello"},
        {"text": "hi"},
        usage={"input": 7, "output": 3},
        duration=1.5,
        cost=0.002,
    )
    run.add_step(StepKind.tool, {"q": 1}, {"ok": True}, tool_info={"name": "lookup"})

    spans = to_otel_genai(run)
    assert len(spans) == 2
    model_span, tool_span = spans
    assert model_span["traceId"] == "native-run" and model_span["spanId"] == step.id
    assert tool_span["parentSpanId"] == step.id
    assert model_span["name"] == "model" and tool_span["name"] == "lookup"

    values = _by_key(model_span)
    assert values[semconv.OPERATION_NAME] == "model"
    assert values[semconv.RESPONSE_MODEL] == "kimi-k2.6"
    assert values[semconv.PROMPT] == {"prompt": "hello"}
    assert values[semconv.COMPLETION] == {"text": "hi"}
    assert values[semconv.INPUT_TOKENS] == 7 and values[semconv.OUTPUT_TOKENS] == 3
    assert values["opentine.cost_usd"] == "0.002"

    start = int(model_span["startTimeUnixNano"])
    assert int(model_span["endTimeUnixNano"]) - start == 1_500_000_000
    assert abs(start / 1_000_000_000 - step.timestamp) < 1e-6
    assert _by_key(tool_span)["opentine.trace.kind"] == "tool"

    # Exporting the run and the events it produces are the same thing.
    assert to_otel_genai(native_events(run)) == spans
    assert to_otel_genai(native_events(run)[0]) == [spans[0]]


def test_v3_repository_run_exports_otel_genai_spans(tmp_path):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    first = recorder.append(
        TraceEvent(
            "model",
            5.0,
            "trace-v3",
            "span-1",
            model="kimi-k2.6",
            inputs={"prompt": "hello"},
            outputs={"text": "hi"},
            usage={"input": 5, "output": 2},
            duration=0.5,
        )
    )
    recorder.append(
        TraceEvent("model", 6.0, "trace-v3", "span-2", parent_span_id="span-1", model="kimi-k2.6")
    )
    run_id = recorder.finalize()

    spans = to_otel_genai(repo.load_run(run_id))
    assert len(spans) == 2
    assert spans[0]["spanId"] == first and spans[1]["parentSpanId"] == first
    assert {span["traceId"] for span in spans} == {run_id}
    assert spans[0]["startTimeUnixNano"] == "5000000000"
    assert spans[0]["endTimeUnixNano"] == "5500000000"
    values = _by_key(spans[0])
    assert values[semconv.RESPONSE_MODEL] == "kimi-k2.6"
    assert values[semconv.INPUT_TOKENS] == 5 and values[semconv.OUTPUT_TOKENS] == 2
    assert values[semconv.PROMPT] == {"prompt": "hello"}


def test_export_document_is_a_complete_otlp_export_the_importer_accepts():
    events = otel_genai_events(SPANS)
    document = to_otel_genai_document(events, service_name="checkout-agent")

    scope = document["resourceSpans"][0]["scopeSpans"][0]
    assert scope["scope"]["name"] == "opentine"
    assert scope["spans"] == to_otel_genai(events)
    resource = document["resourceSpans"][0]["resource"]["attributes"][0]
    assert resource == {"key": "service.name", "value": {"stringValue": "checkout-agent"}}
    assert otel_genai_events(document) == events


@pytest.mark.parametrize("version", sorted(path.name for path in COMPAT.iterdir() if path.is_dir()))
def test_runs_written_by_every_release_since_0_3_0_still_export(version, tmp_path):
    """The compat gate for the exporter: it reads what older releases wrote.

    Nothing here regenerates or mutates a fixture — the repository is copied out
    read-only exactly as ``test_backwards_compat`` does, and export only reads.
    """
    artifact = to_otel_genai(Run.load(COMPAT / version / "artifact.tine"))
    assert [span["name"] for span in artifact] == ["model", "search", "model", "model"]
    assert [_by_key(span)["legacy_kind"] for span in artifact] == ["model", "tool", "think", "done"]
    assert _by_key(artifact[0])[semconv.RESPONSE_MODEL] == "anthropic/claude-sonnet-5"
    assert all(int(span["endTimeUnixNano"]) >= int(span["startTimeUnixNano"]) for span in artifact)

    destination = tmp_path / "repo"
    shutil.copytree(COMPAT / version / "repo", destination)
    spans = to_otel_genai(Repo.open(destination).load_run("heads/main"))
    assert len(spans) == 4
    assert {span["traceId"] for span in spans} == {f"compat-repo-source-{version}"}
    assert semconv.OPERATION_NAME in _by_key(spans[0])
    assert otel_genai_events(spans)[0].span_id == spans[0]["spanId"]


def test_export_refuses_records_that_are_not_trace_events():
    with pytest.raises(TypeError, match="requires TraceEvent records"):
        to_otel_genai([{"span_id": "not-an-event"}])


def test_export_bounds_the_number_of_exported_spans(monkeypatch):
    import opentine.trace.exporters as module

    monkeypatch.setattr(module, "MAX_EXPORTED_SPANS", 1)
    events = [TraceEvent("model", 0, "t", str(index)) for index in range(2)]
    with pytest.raises(ValueError, match="maximum span count"):
        to_otel_genai(events)
    with pytest.raises(ValueError, match="maximum span count"):
        to_otel_genai(iter(events))


def test_attribute_encoding_is_bounded_and_decodes_to_what_it_encoded():
    nested: object = "bottom"
    for _ in range(120):
        nested = [nested]
    with pytest.raises(ValueError, match="maximum nesting depth"):
        encode_any_value(nested)

    span = {"attributes": [{"key": "value", "value": encode_any_value({"a": [1, 1.5, True, "x"]})}]}
    assert decoded_attributes(span) == {"value": {"a": [1, 1.5, True, "x"]}}


def test_export_encodes_oversized_integers_the_way_the_importer_reads_them():
    event = TraceEvent("model", 0, "t", "s", attributes={"large": 2**63, "empty": None})
    span = to_otel_genai(event)[0]
    assert {"key": "large", "value": {"stringValue": str(2**63)}} in span["attributes"]
    # OTLP has no null AnyValue, so a None-valued attribute is dropped, not faked.
    assert all(item["key"] != "empty" for item in span["attributes"])
    assert _by_key(span)["large"] == str(2**63)


def test_native_run_kinds_survive_export_and_reimport():
    """A native run's tool/think/done steps carry a kind the GenAI operation name
    cannot express. Export writes opentine.trace.kind and the importer reads it
    back, so export->import preserves every kind instead of collapsing them to
    the operation-derived default. Without the read-back this round trip loses
    the non-model kinds."""
    run = Run(id="kind-roundtrip")
    run.add_step(StepKind.model, {"p": "hi"}, {"o": "there"}, model_info="anthropic/x")
    run.add_step(StepKind.tool, {"q": "lookup"}, {"r": "row"}, tool_info={"name": "search"})
    run.add_step(StepKind.think, {"text": "reflect"})
    run.add_step(StepKind.done, {"text": "final"}, {"text": "done"})

    native = native_events(run)
    reimported = otel_genai_events(to_otel_genai(native))
    assert [event.kind for event in reimported] == [event.kind for event in native]
    # The read-back consumes the marker, so it never lingers as a stray attribute.
    assert all(semconv.KIND_ATTRIBUTE not in event.attributes for event in reimported)
