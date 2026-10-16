"""Import OTLP/JSON GenAI spans, including the Claude Code span dialect.

Split out of :mod:`opentine.trace.importers` (which re-exports
:func:`otel_genai_events`) so both stay inside the per-module line budget.
Claude Code's spans carry their token counts as bare attributes and set no
``gen_ai.usage.*``; :func:`opentine.trace._otel_dialects.claude_span` reads
them, so a Claude Code trace imports priced instead of as unpriced model calls.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from opentine._jsonsafe import json_safe as _safe
from opentine.trace import _genai_semconv as semconv
from opentine.trace._import_helpers import first as _first
from opentine.trace._import_helpers import integer as _int
from opentine.trace._import_helpers import otel_spans
from opentine.trace._import_helpers import timestamp as _timestamp
from opentine.trace._otel_accounting import otel_accounting
from opentine.trace._otel_content import span_content as _span_content
from opentine.trace._otel_dialects import claude_span
from opentine.trace._otel_ids import imported_ids
from opentine.trace._otel_usage import bill_unreported_agents, otel_usage, span_kind
from opentine.trace._otel_values import attributes as _attributes
from opentine.trace._provider_alias import canonical_provider
from opentine.trace.schema import TraceEvent


def otel_genai_events(
    spans: Iterable[dict[str, Any]] | dict[str, Any],
) -> list[TraceEvent]:
    # Looked up at call time: the limits live (and are tuned) on the importers
    # module, which imports this one.
    from opentine.trace import importers

    events: list[TraceEvent] = []
    total, inferred = 0, set[int]()
    for span in otel_spans(spans):
        if len(events) >= importers.MAX_TRACE_EVENTS:
            raise ValueError("trace import exceeds maximum event count")
        total = importers._consume(total, span)
        try:
            attributes = _attributes(span)
        except (RecursionError, ValueError):
            continue
        operation = str(attributes.get(semconv.OPERATION_NAME, span.get("name", "")))
        dialect = claude_span(str(span.get("name") or ""), attributes)
        if dialect is not None and dialect.get("skip"):
            continue
        usage, attributes = otel_usage(attributes)
        # A native run's kind rides in an OpenTine attribute when the operation
        # name cannot carry it; read it back (and drop it) so export->import
        # restores tool/think/error instead of collapsing them to "model".
        kind = span_kind(attributes, operation, inferred, len(events))
        if dialect is not None:
            kind, usage = dialect["kind"], usage or dialect.get("usage", {})
        # Money rides in OpenTine attributes for the same reason; read it back
        # too, or a priced run re-imports at $0.00 with its billing dropped.
        cost, billing = otel_accounting(attributes)
        nanos = _int(_first(span, "startTimeUnixNano", "start_time_unix_nano", default=0))
        end_nanos = _int(_first(span, "endTimeUnixNano", "end_time_unix_nano", default=nanos))
        model = attributes.get(semconv.RESPONSE_MODEL) or attributes.get(semconv.REQUEST_MODEL)
        inputs, outputs = _span_content(span, attributes)
        if dialect is not None:
            model = model or dialect.get("model")
            inputs, outputs = (
                {**dialect.get("inputs", {}), **inputs}
                if isinstance(inputs, dict)
                else inputs or dialect.get("inputs", {}),
                outputs or dialect.get("outputs", {}),
            )
            operation = dialect.get("actor") or operation
        # The ids an export replaced with OTLP-shaped ones come back from attributes.
        trace_id, span_id, parent_id, causal = imported_ids(span, attributes, len(events))
        events.append(
            TraceEvent(
                kind=kind,
                timestamp=_timestamp(nanos) / 1_000_000_000,
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=parent_id,
                causal_span_ids=causal,
                actor=operation,
                model=str(model or ""),
                provider=canonical_provider(_first(attributes, *semconv.PROVIDER_KEYS, default="")),
                cost=cost,
                duration=max(0, _timestamp(end_nanos - nanos)) / 1_000_000_000,
                inputs=_safe(inputs),
                outputs=_safe(outputs),
                usage=usage,
                billing=_safe(billing),
                attributes=_safe(attributes),
            )
        )
    return bill_unreported_agents(events, inferred)
