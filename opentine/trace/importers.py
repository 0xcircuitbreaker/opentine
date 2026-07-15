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

from opentine._jsonsafe import json_safe as _safe
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

MAX_TRACE_EVENTS = 100_000
MAX_JSONL_LINE_BYTES = 16 * 1024 * 1024


def _file_lines(path: str | Path):
    with Path(path).open("rb") as handle:
        while line := handle.readline(MAX_JSONL_LINE_BYTES + 1):
            oversized = len(line) > MAX_JSONL_LINE_BYTES
            while oversized and not line.endswith(b"\n"):
                line = handle.readline(MAX_JSONL_LINE_BYTES + 1)
                if not line:
                    break
            if not oversized:
                yield line


def _optional_string(value: Any) -> str | None:
    return None if value is None or value == "" else str(value)


def _kind(value: Any) -> str:
    normalized = str(value or "model").casefold()
    if normalized in {"model", "tool", "human", "policy", "approval", "subagent", "error"}:
        return normalized
    if "tool" in normalized:
        return "tool"
    if "error" in normalized or "exception" in normalized:
        return "error"
    return "model"


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
                cost=step.cost,
                duration=step.duration,
                inputs=_safe(step.inputs),
                outputs=_safe(step.outputs),
                usage=_safe(step.usage),
                billing=_safe(step.billing),
                attributes={"index": index, "legacy_kind": step.kind.value},
            )
        )
    return events


def jsonl_events(source: str | Path | Iterable[str]) -> list[TraceEvent]:
    lines = _file_lines(source) if isinstance(source, (str, Path)) else source
    events: list[TraceEvent] = []
    for line in lines:
        if not isinstance(line, (str, bytes)) or len(line) > MAX_JSONL_LINE_BYTES:
            continue
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except (json.JSONDecodeError, RecursionError, TypeError, UnicodeDecodeError):
            continue
        if not isinstance(item, dict):
            continue
        if len(events) >= MAX_TRACE_EVENTS:
            raise ValueError("trace import exceeds maximum event count")
        causal = item.get("causal_span_ids") or ()
        events.append(
            TraceEvent(
                kind=_kind(item.get("kind", item.get("type", "model"))),
                timestamp=_timestamp(_first(item, "timestamp", "time", "ts", default=0)),
                trace_id=str(_first(item, "trace_id", "run_id", default="imported")),
                span_id=str(_first(item, "span_id", "id", default=len(events))),
                parent_span_id=_optional_string(_first(item, "parent_span_id", "parent_id")),
                causal_span_ids=tuple(str(value) for value in causal)
                if isinstance(causal, (list, tuple))
                else (),
                actor=str(item.get("actor", "")),
                model=str(item.get("model", "")),
                cost=_safe(item.get("cost")),
                duration=max(0, _timestamp(item.get("duration", item.get("latency", 0)))),
                inputs=_safe(_mapping(_first(item, "inputs", "input"))),
                outputs=_safe(_mapping(_first(item, "outputs", "output"))),
                usage=_safe(dictionary(item.get("usage"))),
                billing=_safe(dictionary(item.get("billing"))),
                attributes=_safe(dictionary(item.get("attributes"))),
            )
        )
    return events


def otel_genai_events(
    spans: Iterable[dict[str, Any]] | dict[str, Any],
) -> list[TraceEvent]:
    events: list[TraceEvent] = []
    for span in otel_spans(spans):
        if len(events) >= MAX_TRACE_EVENTS:
            raise ValueError("trace import exceeds maximum event count")
        attributes = _attributes(span)
        operation = str(attributes.get("gen_ai.operation.name", span.get("name", "")))
        kind = _kind(operation)
        usage = _safe(
            {
                "input": _int(attributes.get("gen_ai.usage.input_tokens")),
                "output": _int(attributes.get("gen_ai.usage.output_tokens")),
            }
        )
        nanos = _int(_first(span, "startTimeUnixNano", "start_time_unix_nano", default=0))
        end_nanos = _int(_first(span, "endTimeUnixNano", "end_time_unix_nano", default=nanos))
        events.append(
            TraceEvent(
                kind=kind,
                timestamp=_timestamp(nanos) / 1_000_000_000,
                trace_id=str(_first(span, "traceId", "trace_id", default="")),
                span_id=str(_first(span, "spanId", "span_id", default=len(events))),
                parent_span_id=_optional_string(_first(span, "parentSpanId", "parent_span_id")),
                causal_span_ids=tuple(
                    str(identifier)
                    for link in span.get("links") or []
                    if isinstance(link, dict)
                    and (identifier := _first(link, "spanId", "span_id")) is not None
                ),
                actor=operation,
                model=str(
                    attributes.get("gen_ai.response.model")
                    or attributes.get("gen_ai.request.model")
                    or ""
                ),
                duration=max(0, _timestamp(end_nanos - nanos)) / 1_000_000_000,
                inputs=_safe(_mapping(span.get("inputs") or attributes.get("gen_ai.prompt"))),
                outputs=_safe(_mapping(span.get("outputs") or attributes.get("gen_ai.completion"))),
                usage=usage,
                attributes=_safe(attributes),
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
        if len(events) >= MAX_TRACE_EVENTS:
            raise ValueError("trace import exceeds maximum event count")
        if not isinstance(record, dict):
            continue
        event_type = str(_first(record, "type", "event", actor_field, default="model")).lower()
        kind = _kind(event_type)
        events.append(
            TraceEvent(
                kind=kind,
                timestamp=_timestamp(
                    _first(record, "timestamp", "start_time", "startTime", "ts", default=0)
                ),
                trace_id=str(_first(record, "trace_id", "run_id", default=framework)),
                span_id=str(_first(record, id_field, "span_id", "id", "run_id", default=index)),
                parent_span_id=_optional_string(
                    _first(record, parent_field, "parent_span_id", "parent_id")
                ),
                actor=str(_first(record, actor_field, "actor", "name", default="")),
                model=str(record.get("model", "")),
                cost=_safe(record.get("cost")),
                duration=max(0, _timestamp(record.get("duration", record.get("latency", 0)))),
                inputs=_safe(
                    _mapping(_first(record, "inputs", "input", "args", "prompt", "messages"))
                ),
                outputs=_safe(_mapping(_first(record, "outputs", "output", "response", "result"))),
                usage=_safe(dictionary(record.get("usage"))),
                attributes=_safe({"framework": framework, **dictionary(record.get("metadata"))}),
            )
        )
    return events
