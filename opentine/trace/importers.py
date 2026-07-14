"""Import OpenTine, JSONL, OpenTelemetry GenAI, and common framework traces.

The JSONL/OTel/framework importers are defensive: they accept real-world shapes
(OTLP camelCase keys and typed ``AnyValue`` attributes, list-shaped chat messages,
ISO-8601 or epoch timestamps) and never raise on a well-formed-but-unexpected record.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from opentine.trace._import_helpers import (
    attributes as _attributes,
)
from opentine.trace._import_helpers import (
    dictionary,
    otel_spans,
)
from opentine.trace._import_helpers import (
    first as _first,
)
from opentine.trace._import_helpers import (
    integer as _int,
)
from opentine.trace._import_helpers import (
    mapping as _mapping,
)
from opentine.trace._import_helpers import (
    timestamp as _timestamp,
)
from opentine.trace.schema import TraceEvent


def native_events(run) -> list[TraceEvent]:
    events: list[TraceEvent] = []
    for index, step in enumerate(run.steps):
        kind = "model"
        if step.kind.value == "tool":
            kind = "tool"
        elif step.kind.value == "error":
            kind = "error"
        events.append(
            TraceEvent(
                kind=kind,
                timestamp=step.timestamp,
                trace_id=run.id,
                span_id=step.id,
                parent_span_id=step.parent_id,
                actor=step.tool_info.get("name", "model"),
                model=step.model_info,
                inputs=step.inputs,
                outputs=step.outputs,
                usage=step.usage,
                billing=step.billing,
                attributes={"index": index, "legacy_kind": step.kind.value},
            )
        )
    return events


def jsonl_events(source: str | Path | Iterable[str]) -> list[TraceEvent]:
    lines = (
        Path(source).read_text(encoding="utf-8").splitlines()
        if isinstance(source, (str, Path))
        else source
    )
    events: list[TraceEvent] = []
    for line in lines:
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            continue
        causal = item.get("causal_span_ids") or ()
        events.append(
            TraceEvent(
                kind=item.get("kind", item.get("type", "model")),
                timestamp=_timestamp(_first(item, "timestamp", "time", "ts", default=0)),
                trace_id=str(_first(item, "trace_id", "run_id", default="imported")),
                span_id=str(_first(item, "span_id", "id", default=len(events))),
                parent_span_id=_first(item, "parent_span_id", "parent_id"),
                causal_span_ids=tuple(str(value) for value in causal)
                if isinstance(causal, (list, tuple))
                else (),
                actor=str(item.get("actor", "")),
                model=str(item.get("model", "")),
                inputs=_mapping(_first(item, "inputs", "input")),
                outputs=_mapping(_first(item, "outputs", "output")),
                usage=dictionary(item.get("usage")),
                billing=dictionary(item.get("billing")),
                attributes=dictionary(item.get("attributes")),
            )
        )
    return events


def otel_genai_events(
    spans: Iterable[dict[str, Any]] | dict[str, Any],
) -> list[TraceEvent]:
    events: list[TraceEvent] = []
    for span in otel_spans(spans):
        attributes = _attributes(span)
        operation = str(attributes.get("gen_ai.operation.name", span.get("name", "")))
        kind = "tool" if "tool" in operation else "model"
        usage = {
            "input": _int(attributes.get("gen_ai.usage.input_tokens")),
            "output": _int(attributes.get("gen_ai.usage.output_tokens")),
        }
        nanos = _int(_first(span, "startTimeUnixNano", "start_time_unix_nano", default=0))
        events.append(
            TraceEvent(
                kind=kind,
                timestamp=nanos / 1_000_000_000,
                trace_id=str(_first(span, "traceId", "trace_id", default="")),
                span_id=str(_first(span, "spanId", "span_id", default="")),
                parent_span_id=_first(span, "parentSpanId", "parent_span_id"),
                actor=operation,
                model=str(
                    attributes.get("gen_ai.response.model")
                    or attributes.get("gen_ai.request.model")
                    or ""
                ),
                inputs=_mapping(span.get("inputs") or attributes.get("gen_ai.prompt")),
                outputs=_mapping(span.get("outputs") or attributes.get("gen_ai.completion")),
                usage=usage,
                attributes=attributes,
            )
        )
    return events


_FRAMEWORK_FIELDS = {
    "langchain": ("run_id", "parent_run_id", "name"),
    "llamaindex": ("id_", "parent_id", "event_type"),
    "autogen": ("id", "parent_id", "sender"),
    "crewai": ("id", "parent_id", "agent"),
    "openai-agents": ("span_id", "parent_id", "type"),
}


def framework_events(records: Iterable[dict[str, Any]], framework: str) -> list[TraceEvent]:
    key = framework.casefold()
    if key not in _FRAMEWORK_FIELDS:
        raise ValueError(f"unsupported framework importer: {framework}")
    id_field, parent_field, actor_field = _FRAMEWORK_FIELDS[key]
    events: list[TraceEvent] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        event_type = str(_first(record, "type", "event", actor_field, default="model")).lower()
        kind = "tool" if "tool" in event_type else "error" if "error" in event_type else "model"
        events.append(
            TraceEvent(
                kind=kind,
                timestamp=_timestamp(
                    _first(record, "timestamp", "start_time", "startTime", "ts", default=0)
                ),
                trace_id=str(_first(record, "trace_id", "run_id", default=framework)),
                span_id=str(_first(record, id_field, "span_id", "id", "run_id", default=index)),
                parent_span_id=_first(record, parent_field, "parent_span_id", "parent_id"),
                actor=str(_first(record, actor_field, "actor", "name", default="")),
                model=str(record.get("model", "")),
                inputs=_mapping(_first(record, "inputs", "input", "args", "prompt", "messages")),
                outputs=_mapping(_first(record, "outputs", "output", "response", "result")),
                usage=dictionary(record.get("usage")),
                attributes={"framework": framework, **dictionary(record.get("metadata"))},
            )
        )
    return events
