"""Emit OpenTine provenance as OpenTelemetry GenAI spans (OTLP/JSON).

The exact inverse of :func:`opentine.trace.otel_genai_events`: the span dicts
produced here are the shape that importer consumes, so
``otel_genai_events(to_otel_genai(events))`` returns the events it was given.
Both directions spell their ``gen_ai.*`` keys through
:mod:`opentine.trace._genai_semconv` so they cannot drift apart.

Export is read-only over provenance. It reads runs through the same public
loaders every release since 0.3.0 exposes, writes nothing, and introduces no
artifact or repository format version.

Known lossy edges, all outside the GenAI conventions:

* ``timestamp``/``duration`` are seconds as ``float``; nanosecond precision
  beyond float64's 53-bit mantissa (roughly microseconds at a 2020s epoch) is
  already gone by the time an event exists, so re-exported nanos may differ in
  the last digits from the ones originally imported.
* ``cost`` and ``billing`` have no GenAI convention. They are emitted under
  ``opentine.*`` so no data is dropped, but the importer does not read them
  back into :class:`~opentine.trace.schema.TraceEvent` fields.
* Attributes whose value is ``None`` are dropped; OTLP has no null ``AnyValue``.

Everything the importer does read survives: ``otel_genai_events(spans)`` and
``otel_genai_events(to_otel_genai(otel_genai_events(spans)))`` compare equal.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol, runtime_checkable

from opentine._jsonsafe import json_safe as _safe
from opentine._version import __version__
from opentine.trace import _genai_semconv as semconv
from opentine.trace._import_helpers import event_kind
from opentine.trace._otel_values import encode_any_value
from opentine.trace.importers import native_events
from opentine.trace.schema import TraceEvent

MAX_EXPORTED_SPANS = 100_000
SCOPE_NAME = "opentine"
KIND_ATTRIBUTE = semconv.KIND_ATTRIBUTE
COST_ATTRIBUTE = "opentine.cost_usd"
BILLING_ATTRIBUTE = "opentine.billing"
_CLIENT_SPAN = "SPAN_KIND_CLIENT"
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
        "kind": _CLIENT_SPAN,
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
        # A zero counter no span ever reported stays absent, so importing a span
        # without usage and exporting it again does not invent attributes.
        if key not in attributes and isinstance(tokens, (int, float)) and tokens > 0:
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
    return attributes


def _nanos(value: float | str) -> int:
    """Seconds to integer nanoseconds, tolerating the stored decimal-string form."""
    try:
        return round(float(value) * _NANOS)
    except (OverflowError, TypeError, ValueError):
        return 0
