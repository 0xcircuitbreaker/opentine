"""Shared conversion of normalized trace records into immutable v3 events."""

from __future__ import annotations

from typing import Any

from opentine._blob_guard import guarded_blob_body
from opentine._canon import _redact
from opentine._jsonsafe import json_safe
from opentine.trace.schema import TraceEvent

SpanKey = tuple[str, str]
SpanMap = dict[SpanKey, str]


def span_key(trace_id: object, span_id: object) -> SpanKey:
    return str(trace_id), str(span_id)


def json_blob(repo: Any, value: Any) -> str:
    return repo.put("blob", guarded_blob_body(value), redact=False)


def put_trace_event(
    repo: Any,
    event: TraceEvent,
    span_map: SpanMap,
    *,
    parent_fallback: str | None = None,
) -> tuple[str, list[str]]:
    current_span = str(event.span_id)
    if (
        event.parent_span_id is not None
        and str(event.parent_span_id) == current_span
        or current_span in {str(value) for value in event.causal_span_ids}
    ):
        raise ValueError("trace parent/causal dependency cycle")
    parent = None
    unresolved_parent: list[str] = []
    if event.parent_span_id is not None:
        parent = span_map.get(span_key(event.trace_id, event.parent_span_id))
        if parent is None:
            unresolved_parent.append(str(event.parent_span_id))
    else:
        parent = parent_fallback
    parents = [parent] if parent else []
    causal: list[str] = []
    unresolved_causal: list[str] = []
    for span in dict.fromkeys(str(value) for value in event.causal_span_ids):
        target = span_map.get(span_key(event.trace_id, span))
        if target is None:
            unresolved_causal.append(span)
        elif target not in causal:
            causal.append(target)
    billing = _redact(json_safe(event.billing))
    cost = event.cost
    if cost is None and isinstance(billing, dict):
        cost = billing.get("known_subtotal_usd", 0)
    payload = {
        "actor": str(event.actor),
        "attributes": _redact(json_safe(event.attributes)),
        "billing": billing,
        "causal_ids": causal,
        "cost": json_safe(cost or 0),
        "duration": json_safe(event.duration),
        "input_blob": json_blob(repo, event.inputs),
        "kind": str(event.kind),
        "model": str(event.model),
        "output_blob": json_blob(repo, event.outputs),
        "parent_ids": parents,
        "span_id": str(event.span_id),
        "time_unix": json_safe(event.timestamp),
        "trace_id": str(event.trace_id),
        "usage": _redact(json_safe(event.usage)),
    }
    # Only when the span named one, exactly as the compatibility writer does: an
    # always-present key would re-address every event imported without a provider.
    if event.provider:
        payload["provider"] = str(event.provider)
    if unresolved_parent or unresolved_causal:
        payload["unresolved_span_refs"] = {
            "causal": unresolved_causal,
            "parent": unresolved_parent,
        }
    return repo.put("event", payload), parents
