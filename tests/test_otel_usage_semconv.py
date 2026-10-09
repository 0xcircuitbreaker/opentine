"""0.8.2: OTel import prices current-convention spans correctly, and agent roll-ups once.

Two confirmed mispricings in shipped code: a span following the current GenAI
conventions (inclusive ``input_tokens`` with a ``cache_read.input_tokens``
sub-count) billed every cached token at the full input rate, and an
``invoke_agent`` span's aggregate usage was billed on top of the model calls
beneath it.
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from opentine._graph_types import V3_ONLY_KINDS, StepKind
from opentine._pricing_pass import price_events, price_run
from opentine.billing import load_catalogs
from opentine.core import Run
from opentine.repository import Repo
from opentine.trace import _genai_semconv as semconv
from opentine.trace._otel_values import attributes as decoded_attributes
from opentine.trace.exporters import to_otel_genai
from opentine.trace.importers import otel_genai_events
from opentine.trace.recorder import Recorder
from opentine.trace.schema import TRACE_KINDS, TraceEvent

# 2026-09-09: inside claude-opus-5's card ($5 in, $0.50 cache read, $25 out).
START = 1_789_000_000_000_000_000
TRACE = "0af7651916cd43dd8448eb211c80319c"


def _value(value):
    return {"intValue": str(value)} if isinstance(value, int) else {"stringValue": str(value)}


def _span(span_id, attributes, *, parent=None, offset=0):
    span = {
        "traceId": TRACE,
        "spanId": span_id,
        "name": attributes.get(semconv.OPERATION_NAME, "chat"),
        "startTimeUnixNano": str(START + offset),
        "endTimeUnixNano": str(START + offset + 1_000_000),
        "attributes": [{"key": key, "value": _value(value)} for key, value in attributes.items()],
    }
    if parent:
        span["parentSpanId"] = parent
    return span


def _chat(span_id, parent=None, offset=0, **counters):
    attributes = {
        semconv.OPERATION_NAME: "chat",
        semconv.PROVIDER_NAME: "anthropic",
        semconv.RESPONSE_MODEL: "claude-opus-5",
        **counters,
    }
    return _span(span_id, attributes, parent=parent, offset=offset)


def _agent(span_id, parent=None, operation="invoke_agent", **counters):
    attributes = {
        semconv.OPERATION_NAME: operation,
        semconv.PROVIDER_NAME: "anthropic",
        semconv.REQUEST_MODEL: "claude-opus-5",
        **counters,
    }
    return _span(span_id, attributes, parent=parent)


def _total(events) -> Decimal:
    priced = price_events(events, catalog=load_catalogs())
    return sum((Decimal(str(event.cost or 0)) for event in priced), Decimal("0"))


TOKENS_IN = "gen_ai.usage.input_tokens"
TOKENS_OUT = "gen_ai.usage.output_tokens"


def test_current_convention_cache_reads_are_inside_input_tokens():
    span = _chat(
        "c1", **{TOKENS_IN: 100_000, semconv.CACHE_READ_INPUT_TOKENS: 90_000, TOKENS_OUT: 1_000}
    )
    (event,) = otel_genai_events([span])
    assert event.usage == {"input": 10_000, "cache_read": 90_000, "output": 1_000}
    # 10k x $5 + 90k x $0.50 + 1k x $25, not 100k x $5 + 1k x $25 = $0.525.
    assert _total([event]) == Decimal("0.12")


@pytest.mark.parametrize(
    "key", [semconv.CACHE_CREATION_INPUT_TOKENS, semconv.CACHE_WRITE_INPUT_TOKENS]
)
def test_both_cache_write_spellings_are_read_and_subtracted(key):
    span = _chat("c1", **{TOKENS_IN: 1_000, semconv.CACHE_READ_INPUT_TOKENS: 300, key: 200})
    (event,) = otel_genai_events([span])
    assert event.usage == {"input": 500, "cache_read": 300, "cache_write_5m": 200}


def test_current_convention_reasoning_is_inside_output_tokens():
    span = _chat("c1", **{TOKENS_OUT: 900, semconv.REASONING_OUTPUT_TOKENS: 600})
    (event,) = otel_genai_events([span])
    assert event.usage == {"output": 300, "reasoning": 600}


def test_deployed_spellings_keep_their_exclusive_reading():
    # Exactly what OpenTine exports up to 0.8.1 wrote: exclusive buckets.
    span = _chat("c1", **{TOKENS_IN: 10_000, semconv.CACHE_READ_TOKENS: 90_000, TOKENS_OUT: 1_000})
    (event,) = otel_genai_events([span])
    assert event.usage == {"input": 10_000, "cache_read": 90_000, "output": 1_000}


def test_a_total_smaller_than_its_sub_counts_is_kept_and_flagged():
    span = _chat("c1", **{TOKENS_IN: 50, semconv.CACHE_READ_INPUT_TOKENS: 90})
    (event,) = otel_genai_events([span])
    assert event.usage == {"input": 50, "cache_read": 90}
    assert any(
        "smaller than its sub-counts" in w for w in event.attributes["opentine.import_warnings"]
    )


AGENT_TRACE = [
    _agent("a1", **{TOKENS_IN: 20_000, TOKENS_OUT: 2_000}),
    _chat("b1", parent="a1", offset=1, **{TOKENS_IN: 10_000, TOKENS_OUT: 1_000}),
    _chat("b2", parent="a1", offset=2, **{TOKENS_IN: 10_000, TOKENS_OUT: 1_000}),
]


def test_an_agent_rollup_is_a_subagent_step_and_is_not_billed_twice():
    events = otel_genai_events(AGENT_TRACE)
    assert [event.kind for event in events] == ["subagent", "model", "model"]
    assert events[0].usage == {"input": 20_000, "output": 2_000}, "the roll-up is still recorded"
    assert _total(events) == Decimal("0.15")


def test_an_agent_span_with_nothing_reported_beneath_it_is_billed():
    remote = [
        _agent("a1", **{TOKENS_IN: 20_000, TOKENS_OUT: 2_000}),
        _span("t1", {semconv.OPERATION_NAME: "execute_tool"}, parent="a1"),
    ]
    events = otel_genai_events(remote)
    assert [event.kind for event in events] == ["model", "tool"]
    assert _total(events) == Decimal("0.15")


def test_nested_agents_bill_only_the_model_calls():
    nested = [
        _agent("a0", **{TOKENS_IN: 20_000, TOKENS_OUT: 2_000}),
        _agent("a1", parent="a0", **{TOKENS_IN: 20_000, TOKENS_OUT: 2_000}),
        *AGENT_TRACE[1:],
    ]
    events = otel_genai_events(nested)
    assert [event.kind for event in events] == ["subagent", "subagent", "model", "model"]
    assert _total(events) == Decimal("0.15")


def test_an_explicit_kind_attribute_is_never_re_inferred():
    span = _agent("a1", **{TOKENS_IN: 20_000, semconv.KIND_ATTRIBUTE: "subagent"})
    assert otel_genai_events([span])[0].kind == "subagent"


def test_agents_without_usage_stay_subagents():
    events = otel_genai_events([_agent("a1", operation="create_agent")])
    assert events[0].kind == "subagent" and events[0].usage == {}


@pytest.mark.parametrize(
    "spans",
    [
        [
            _chat(
                "c1",
                **{TOKENS_IN: 100_000, semconv.CACHE_READ_INPUT_TOKENS: 90_000, TOKENS_OUT: 10},
            )
        ],
        [_chat("c1", **{TOKENS_IN: 10_000, semconv.CACHE_READ_TOKENS: 90_000, TOKENS_OUT: 10})],
        AGENT_TRACE,
    ],
)
def test_imported_spans_re_export_with_the_attributes_they_arrived_with(spans):
    events = otel_genai_events(spans)
    exported = to_otel_genai(events)
    for original, again in zip(spans, exported, strict=True):
        before = decoded_attributes(original)
        after = decoded_attributes(again)
        assert {key: after[key] for key in before} == before
        assert semconv.USAGE_ATTRIBUTE not in after
    assert [event.usage for event in otel_genai_events(exported)] == [e.usage for e in events]


@pytest.mark.parametrize(
    "usage",
    [
        {"input": 11, "output": 7, "cache_read": 90, "cache_write_5m": 5, "reasoning": 21},
        {"cache_read": 40},
        {"input": 1, "cache_write_1h": 9},
        {"input": 3, "output": 4, "input_audio": 7},
        {"output": 0},
    ],
)
def test_native_usage_survives_export_and_import_exactly(usage):
    event = TraceEvent("model", 1.0, "t", "s", actor="chat", provider="anthropic", usage=usage)
    (span,) = to_otel_genai([event])
    attributes = decoded_attributes(span)
    assert attributes[semconv.SYSTEM] == attributes[semconv.PROVIDER_NAME] == "anthropic"
    assert otel_genai_events([span])[0].usage == usage


def _repository_run(tmp_path: Path) -> Run:
    repo = Repo.init(tmp_path / "repo")
    recorder = Recorder.start(repo, ref="heads/main", capture=False)
    recorder.import_events(otel_genai_events(AGENT_TRACE))
    return repo.load_run(recorder.finalize())


def test_a_subagent_rollup_is_not_re_billed_after_saving_to_tine(tmp_path):
    run = _repository_run(tmp_path)
    run.save(tmp_path / "run.tine")
    loaded = Run.load(tmp_path / "run.tine")
    assert [step.v3_kind for step in loaded.steps] == ["subagent", None, None]
    assert loaded.steps[0].kind is StepKind.model, "the legacy enum still reads it"
    for candidate in (run, loaded):
        assert Decimal(str(price_run(candidate).total_cost)) == Decimal("0.15")
        breakdown = candidate.cost_breakdown()
        assert (breakdown.input_tokens, breakdown.output_tokens) == (20_000, 2_000)


def test_v3_only_kinds_are_exactly_the_trace_kinds_the_legacy_enum_lacks():
    assert V3_ONLY_KINDS == TRACE_KINDS - {kind.value for kind in StepKind}
