"""Normalized trace importer fixtures."""

from __future__ import annotations

import json

import pytest

from opentine import Run, StepKind
from opentine.trace import framework_events, jsonl_events, native_events, otel_genai_events


def test_native_jsonl_and_otel_importers(tmp_path):
    run = Run(id="native", model_info="model")
    step = run.add_step(StepKind.done, {"text": "ok"}, usage={"input": 3, "output": 1})
    native = native_events(run)
    assert native[0].span_id == step.id and native[0].usage["input"] == 3
    assert native[0].cost == step.cost and native[0].duration == step.duration

    path = tmp_path / "trace.jsonl"
    path.write_text(
        json.dumps(
            {
                "kind": "tool",
                "timestamp": 1,
                "trace_id": "t",
                "span_id": "s",
                "inputs": {"name": "lookup"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    assert jsonl_events(path)[0].kind == "tool"

    spans = [
        {
            "name": "chat",
            "trace_id": "trace",
            "span_id": "span",
            "start_time_unix_nano": 2_000_000_000,
            "end_time_unix_nano": 3_500_000_000,
            "attributes": {
                "gen_ai.operation.name": "chat",
                "gen_ai.request.model": "gpt-5.6",
                "gen_ai.usage.input_tokens": 5,
                "gen_ai.usage.output_tokens": 2,
            },
        }
    ]
    imported = otel_genai_events(spans)[0]
    assert imported.timestamp == 2 and imported.usage == {"input": 5, "output": 2}
    assert imported.duration == 1.5


@pytest.mark.parametrize(
    "framework", ["langchain", "llamaindex", "autogen", "crewai", "openai-agents"]
)
def test_framework_importers(framework):
    event = framework_events(
        [{"id": "1", "type": "tool_call", "input": {"q": 1}, "output": {"ok": True}}],
        framework,
    )[0]
    assert event.kind == "tool"
    assert event.attributes["framework"] == framework


def test_framework_identity_cannot_be_spoofed_by_imported_metadata():
    event = framework_events(
        [{"id": "1", "metadata": {"framework": "spoofed", "kept": True}}],
        "langchain",
    )[0]
    assert event.attributes == {"framework": "langchain", "kept": True}


def test_otel_importer_parses_real_otlp_json():
    # Real OTLP/JSON: camelCase keys and typed AnyValue attribute values.
    spans = [
        {
            "name": "chat",
            "traceId": "abc",
            "spanId": "def",
            "parentSpanId": "root",
            "startTimeUnixNano": "1784034408576553954",
            "attributes": [
                {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-5.6"}},
                {"key": "gen_ai.usage.input_tokens", "value": {"intValue": "120"}},
                {"key": "gen_ai.usage.output_tokens", "value": {"intValue": "45"}},
            ],
        }
    ]
    event = otel_genai_events(spans)[0]
    assert event.trace_id == "abc" and event.span_id == "def"
    assert event.parent_span_id == "root" and event.model == "gpt-5.6"
    assert event.usage == {"input": 120, "output": 45}
    assert event.timestamp > 0


def test_jsonl_importer_handles_iso_timestamp_and_list_messages():
    line = json.dumps(
        {
            "kind": "model",
            "timestamp": "2026-07-14T00:00:00Z",
            "trace_id": "t",
            "span_id": "s",
            "inputs": [{"role": "user", "content": "hi"}],
        }
    )
    event = jsonl_events([line])[0]
    assert event.timestamp > 0  # ISO-8601 parsed, not crashed
    assert event.inputs == {"messages": [{"role": "user", "content": "hi"}]}


def test_framework_importer_survives_list_shaped_messages():
    event = framework_events(
        [{"id": "1", "type": "tool_call", "input": [{"role": "user", "content": "x"}]}],
        "langchain",
    )[0]
    assert event.kind == "tool"
    assert event.inputs == {"messages": [{"role": "user", "content": "x"}]}


def test_otel_importer_accepts_complete_export_and_defensive_anyvalues():
    document = {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "traceId": "trace",
                                "spanId": "span",
                                "startTimeUnixNano": "2000000000",
                                "attributes": [
                                    {
                                        "key": "gen_ai.operation.name",
                                        "value": {"stringValue": "chat"},
                                    },
                                    {"key": "flag", "value": {"boolValue": "false"}},
                                    {
                                        "key": "large_id",
                                        "value": {"intValue": "9223372036854775807"},
                                    },
                                    42,
                                ],
                            }
                        ]
                    }
                ]
            }
        ]
    }
    event = otel_genai_events(document)[0]
    assert event.timestamp == 2
    assert event.attributes["flag"] is False
    assert event.attributes["large_id"] == "9223372036854775807"


def test_imported_invalid_core_usage_is_discarded_with_warning():
    events = jsonl_events(
        [
            json.dumps(
                {
                    "span_id": "bad-usage",
                    "usage": {"input": 2**63, "output": 1.5, "reasoning": -1},
                }
            )
        ]
    )
    assert events[0].usage == {}
    assert len(events[0].attributes["opentine.import_warnings"]) == 3


def test_importers_skip_well_formed_unexpected_records():
    assert jsonl_events(["[]", '"scalar"']) == []
    assert otel_genai_events([{"attributes": [42]}, [], "span"]) == []
    assert framework_events([[], "record"], "langchain") == []


def test_jsonl_naive_iso_timestamp_is_deterministically_utc():
    event = jsonl_events(
        [json.dumps({"timestamp": "1970-01-01T00:00:01", "trace_id": "t", "span_id": "s"})]
    )[0]
    assert event.timestamp == 1


def test_importers_enforce_aggregate_payload_and_accounting_bounds(monkeypatch):
    import opentine.trace.importers as module

    monkeypatch.setattr(module, "MAX_TRACE_IMPORT_BYTES", 32)
    with pytest.raises(ValueError, match="aggregate payload limit"):
        jsonl_events([json.dumps({"span_id": "x", "inputs": {"text": "x" * 40}})])
    monkeypatch.setattr(module, "MAX_TRACE_IMPORT_BYTES", 1024)
    with pytest.raises(ValueError, match="trace cost must be finite"):
        jsonl_events([json.dumps({"span_id": "x", "cost": -1})])


def test_importer_bound_counts_empty_and_repeated_containers(monkeypatch):
    import opentine.trace.importers as module

    shared: dict = {}
    monkeypatch.setattr(module, "MAX_TRACE_IMPORT_BYTES", 128)
    with pytest.raises(ValueError, match="aggregate payload limit"):
        framework_events([{"input": [shared] * 20}], "langchain")
    monkeypatch.setattr(module, "MAX_TRACE_IMPORT_BYTES", 1_000_000)
    with pytest.raises(ValueError, match="unsupported set payload"):
        framework_events([{"input": {str(index) for index in range(10_000)}}], "langchain")


def test_iterable_jsonl_bound_counts_oversized_skipped_records(monkeypatch):
    import opentine.trace.importers as module

    monkeypatch.setattr(module, "MAX_JSONL_LINE_BYTES", 16)
    monkeypatch.setattr(module, "MAX_TRACE_IMPORT_BYTES", 64)
    with pytest.raises(ValueError, match="aggregate payload limit"):
        jsonl_events(["x" * 17])


def test_malformed_iterables_are_bounded_even_when_no_events_are_emitted(monkeypatch):
    import opentine.trace._import_helpers as helpers
    import opentine.trace.importers as module

    monkeypatch.setattr(module, "MAX_TRACE_EVENTS", 3)
    with pytest.raises(ValueError, match="input-record count"):
        jsonl_events(["", "", "", ""])
    with pytest.raises(ValueError, match="input-record count"):
        framework_events([None, None, None, None], "langchain")

    monkeypatch.setattr(helpers, "_MAX_INPUT_RECORDS", 3)
    with pytest.raises(ValueError, match="input-record count"):
        otel_genai_events([None, None, None, None])


def test_otel_importer_skips_cyclic_anyvalue_and_keeps_following_span():
    cyclic: dict = {}
    cyclic["arrayValue"] = {"values": [cyclic]}
    spans = [
        {
            "traceId": "bad",
            "spanId": "cycle",
            "attributes": [{"key": "cycle", "value": cyclic}],
        },
        {
            "traceId": "good",
            "spanId": "kept",
            "attributes": [{"key": "name", "value": {"stringValue": "ok"}}],
        },
    ]
    events = otel_genai_events(spans)
    assert [event.span_id for event in events] == ["kept"]
    assert events[0].attributes["name"] == "ok"


def test_otel_importer_skips_excessively_deep_anyvalue():
    nested: dict = {"stringValue": "bottom"}
    for _ in range(120):
        nested = {"arrayValue": {"values": [nested]}}
    assert (
        otel_genai_events(
            [
                {
                    "traceId": "bad",
                    "spanId": "deep",
                    "attributes": [{"key": "deep", "value": nested}],
                }
            ]
        )
        == []
    )
