"""Emit OpenTine provenance as OpenTelemetry GenAI spans (OTLP/JSON).

The exact inverse of :func:`opentine.trace.otel_genai_events`: the span dicts
produced here are the shape that importer consumes, so
``otel_genai_events(to_otel_genai(events))`` returns the events it was given.
Both directions spell their ``gen_ai.*`` keys through
:mod:`opentine.trace._genai_semconv` so they cannot drift apart.

Every span carries two content generations at once: the 1.27 ``gen_ai.prompt`` /
``gen_ai.completion`` attributes every deployed reader (this package's importer
included) understands, and the 1.36 ``gen_ai.input.messages`` /
``gen_ai.output.messages`` arrays current backends — Arize Phoenix, Langfuse —
render as a conversation, under the scope ``schemaUrl`` that names them.

Export is read-only over provenance. It reads runs through the same public
loaders every release since 0.3.0 exposes, writes nothing, and introduces no
artifact or repository format version.

Known lossy edges, all outside the GenAI conventions:

* ``timestamp``/``duration`` are seconds as ``float``; nanosecond precision
  beyond float64's 53-bit mantissa (roughly microseconds at a 2020s epoch) is
  already gone by the time an event exists, so re-exported nanos may differ in
  the last digits from the ones originally imported.
* ``cost`` and ``billing`` have no GenAI convention, so they ride under
  ``opentine.*``; the importer reads both back, a cost as the exact decimal
  string written here rather than as the float it may have started as.
* Usage dimensions outside the token counters GenAI names (an ``eval_seconds``,
  say) have no attribute to ride in, so they do not survive the round trip.
* Attributes whose value is ``None`` are dropped; OTLP has no null ``AnyValue``.

Everything the importer does read survives: ``otel_genai_events(spans)`` and
``otel_genai_events(to_otel_genai(otel_genai_events(spans)))`` compare equal.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any, Protocol, runtime_checkable

from opentine._jsonsafe import json_exact as _safe
from opentine._version import __version__
from opentine.trace import _genai_semconv as semconv
from opentine.trace._import_helpers import event_kind
from opentine.trace._otel_values import encode_any_value
from opentine.trace.importers import native_events
from opentine.trace.schema import TraceEvent

MAX_EXPORTED_SPANS = 100_000
#: Upper bound on 1.36 messages rendered per side. The 1.27 attribute still
#: carries the whole payload, so this bounds the rendering, never the content.
MAX_EXPORTED_MESSAGES = 10_000
SCOPE_NAME = "opentine"
SCHEMA_URL = semconv.SCHEMA_URL
KIND_ATTRIBUTE = semconv.KIND_ATTRIBUTE
#: Cost and billing stay OpenTine-namespaced on purpose (see the semconv module,
#: which spells both keys for the reader half too — a key only one direction
#: knows is how the money went missing across a round trip in the first place).
COST_ATTRIBUTE = semconv.COST_ATTRIBUTE
BILLING_ATTRIBUTE = semconv.BILLING_ATTRIBUTE
_CLIENT_SPAN = "SPAN_KIND_CLIENT"
_INTERNAL_SPAN = "SPAN_KIND_INTERNAL"
#: Event kind -> OTLP span kind: a model step leaves the process for a provider
#: API (CLIENT); every other step is in-process work (INTERNAL, the kind the
#: GenAI conventions give ``execute_tool``).
_SPAN_KINDS = {"model": _CLIENT_SPAN}
_ERROR_STATUS = {"code": "STATUS_CODE_ERROR"}
_NANOS = 1_000_000_000


@runtime_checkable
class RunLike(Protocol):
    """Anything exposing OpenTine steps: a ``Run``, or ``Repo.load_run`` output."""

    @property
    def steps(self) -> list[Any]: ...


ExportSource = TraceEvent | RunLike | Iterable[TraceEvent]


def to_otel_genai(source: ExportSource) -> list[dict[str, Any]]:
    """Render run provenance as OpenTelemetry GenAI spans.

    ``source`` is a :class:`~opentine.trace.schema.TraceEvent`, an iterable of
    them, or anything with ``.steps`` — a v2 ``Run``, a ``.tine`` file loaded
    with ``Run.load``, or a v3 repository run from ``repo.load_run(ref)``.
    """
    return [_span(event) for event in _events(source)]


def to_otel_genai_document(
    source: ExportSource, *, service_name: str = SCOPE_NAME
) -> dict[str, Any]:
    """Wrap :func:`to_otel_genai` spans in a complete OTLP/JSON export document."""
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": encode_any_value(str(service_name))}
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": SCOPE_NAME, "version": __version__},
                        "spans": to_otel_genai(source),
                        # Name the convention the attributes follow, so a
                        # collector transforms rather than guesses.
                        "schemaUrl": SCHEMA_URL,
                    }
                ],
            }
        ]
    }


def _events(source: ExportSource) -> list[TraceEvent]:
    if isinstance(source, TraceEvent):
        events = [source]
    elif hasattr(source, "steps"):
        events = native_events(source)
    else:
        events = []
        for event in source:
            if len(events) >= MAX_EXPORTED_SPANS:
                raise ValueError("trace export exceeds maximum span count")
            events.append(event)
    if len(events) > MAX_EXPORTED_SPANS:
        raise ValueError("trace export exceeds maximum span count")
    for event in events:
        if not isinstance(event, TraceEvent):
            raise TypeError("trace export requires TraceEvent records")
    return events


def _span(event: TraceEvent) -> dict[str, Any]:
    attributes = _attributes(event)
    start = _nanos(event.timestamp)
    span: dict[str, Any] = {
        "name": str(attributes.get(semconv.OPERATION_NAME) or event.actor or event.kind),
        "kind": _SPAN_KINDS.get(event.kind, _INTERNAL_SPAN),
        "traceId": event.trace_id,
        "spanId": event.span_id,
        "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(start + max(0, _nanos(event.duration))),
        "attributes": [
            {"key": key, "value": encode_any_value(value)}
            for key, value in attributes.items()
            if value is not None
        ],
    }
    if event.parent_span_id:
        span["parentSpanId"] = event.parent_span_id
    if event.causal_span_ids:
        # The importer reads causal edges out of links, so write them back there.
        span["links"] = [
            {"traceId": event.trace_id, "spanId": span_id} for span_id in event.causal_span_ids
        ]
    if event.kind == "error":
        span["status"] = dict(_ERROR_STATUS)
    return span


def _attributes(event: TraceEvent) -> dict[str, Any]:
    """Carry imported attributes through, filling ``gen_ai.*`` gaps from fields.

    An imported event still holds the span's original attributes, so passing
    them through verbatim is what makes the round trip exact — the derived
    values below only fill in what a span never carried, which is the whole
    attribute set for a natively recorded run.
    """
    attributes = dict(_safe(event.attributes))
    if event.actor and semconv.OPERATION_NAME not in attributes:
        attributes[semconv.OPERATION_NAME] = event.actor
    if event.model and not any(key in attributes for key in semconv.MODEL_KEYS):
        attributes[semconv.RESPONSE_MODEL] = event.model
    for key, payload in ((semconv.PROMPT, event.inputs), (semconv.COMPLETION, event.outputs)):
        if payload and key not in attributes:
            attributes[key] = _safe(payload)
    for dimension, key in semconv.USAGE_BY_DIMENSION.items():
        tokens = event.usage.get(dimension)
        # Every counter the event carries goes out, zero included: the importer
        # reads back only the counters present, so this is exactly reversible.
        if key not in attributes and isinstance(tokens, (int, float)) and tokens >= 0:
            attributes[key] = int(tokens)
    operation = str(attributes.get(semconv.OPERATION_NAME, ""))
    # Only when the operation name cannot carry the kind back: the importer
    # derives kind from it, so a repair attribute on every span would be noise
    # that also stopped imported spans from re-exporting byte-identically.
    if event_kind(operation) != event.kind:
        attributes[KIND_ATTRIBUTE] = event.kind
    if event.cost is not None:
        attributes[COST_ATTRIBUTE] = str(event.cost)
    if event.billing:
        attributes[BILLING_ATTRIBUTE] = _safe(event.billing)
    # The 1.36 rendering of the same content, always last: the importer consumes
    # these two keys, so re-exporting an imported span re-appends them here, and
    # writing them anywhere else would reorder the attribute list on every hop.
    for (key, role), payload in zip(semconv.MESSAGE_ATTRIBUTES, (event.inputs, event.outputs)):
        if payload and key not in attributes:
            attributes[key] = _messages(_safe(payload), role)
    return attributes


def _messages(payload: Any, role: str) -> list[dict[str, Any]]:
    """Render a payload as semconv 1.36 messages: ``{role, parts: [{type, content}]}``.

    A payload already shaped like a chat — ``{"messages": [...]}``, what every
    OpenTine importer normalizes to — keeps its roles and identifying fields;
    anything else (a step's ``{"prompt": ...}``, a scalar completion) becomes one
    message under *role*, so a modern backend renders it rather than nothing.
    """
    entries = payload.get("messages") if isinstance(payload, dict) else None
    if not isinstance(entries, list) or not entries:
        entries = [payload.get("value", payload) if isinstance(payload, dict) else payload]
    messages: list[dict[str, Any]] = []
    for entry in entries[:MAX_EXPORTED_MESSAGES]:
        source = entry if isinstance(entry, dict) else {"content": entry}
        content = source.get("content", "" if source.get("role") else source)
        message: dict[str, Any] = {
            "role": str(source.get("role") or role),
            "parts": [{"type": semconv.TEXT_PART, "content": _text(content)}],
        }
        for field in semconv.CARRIED_FIELDS:
            if source.get(field) is not None:
                message[field] = source[field]
        messages.append(message)
    return messages


def _text(value: Any) -> str:
    """Message-part text for a payload; a structure is rendered as its JSON."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (RecursionError, TypeError, ValueError):
        return str(value)


def _nanos(value: float | str) -> int:
    """Seconds to integer nanoseconds, tolerating the stored decimal-string form."""
    try:
        return round(float(value) * _NANOS)
    except (OverflowError, TypeError, ValueError):
        return 0
