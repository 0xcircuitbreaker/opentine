"""Cross-object structural checks for immutable run event graphs."""

from __future__ import annotations

import math
from decimal import Decimal, InvalidOperation
from typing import Any

from opentine.kernel import KernelError, ObjectEnvelope

_MAX_SAFE_INTEGER = (1 << 53) - 1
_TOKEN_USAGE = {
    "input",
    "output",
    "cache_read",
    "cache_write_5m",
    "cache_write_1h",
    "reasoning",
    "total",
}


def _meter(value: Any, label: str, *, nonnegative: bool = True) -> None:
    try:
        if isinstance(value, str) and len(value) > 128:
            raise InvalidOperation
        number = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise KernelError(f"{label} must be finite and non-negative") from exc
    if isinstance(value, bool) or not number.is_finite() or (nonnegative and number < 0):
        raise KernelError(f"{label} must be finite and non-negative")


def compatibility_float(value: Any, label: str) -> float:
    _meter(value, label)
    number = float(value)
    if not math.isfinite(number):
        raise KernelError(f"{label} exceeds compatibility numeric range")
    return number


def validate_event_metrics(envelope: ObjectEnvelope) -> None:
    if envelope.object_type != "event":
        return
    payload = envelope.payload()
    for field in ("cost", "duration"):
        _meter(payload.get(field, 0), f"event {field}")
    if "time_unix" in payload:
        _meter(payload["time_unix"], "event time_unix", nonnegative=False)
    usage = payload.get("usage") or {}
    if not isinstance(usage, dict):
        raise KernelError("event usage must be a mapping")
    for name, value in usage.items():
        if not isinstance(name, str) or type(value) not in {int, float}:
            raise KernelError(f"event usage.{name} must be numeric")
        _meter(value, f"event usage.{name}")
        number = Decimal(str(value))
        if name in _TOKEN_USAGE and (
            number != number.to_integral_value() or number > _MAX_SAFE_INTEGER
        ):
            raise KernelError(f"event usage.{name} must be a safe integer token count")


def graph_tips(repo: Any, events: list[str]) -> list[str]:
    """Return parent-graph leaves in the supplied stable event order."""
    parents = {
        parent
        for event_id in events
        for parent in (repo.get(event_id).payload().get("parent_ids") or [])
    }
    return [event_id for event_id in events if event_id not in parents]


def filtered_legacy_refs(payload: dict[str, Any], keep: set[str]) -> dict[str, str]:
    return {
        name: target
        for name, target in (payload.get("legacy_refs") or {}).items()
        if target in keep
    }


def validate_run_graph(repo: Any, envelope: ObjectEnvelope) -> None:
    """Validate graph closure and exact roots/tips when all events are present."""
    if envelope.object_type != "run":
        return
    payload = envelope.payload()
    events = list(payload.get("events") or [])
    event_set = set(events)
    legacy_refs = payload.get("legacy_refs", {})
    if not isinstance(legacy_refs, dict) or any(
        not isinstance(name, str) or not isinstance(target, str) or target not in event_set
        for name, target in legacy_refs.items()
    ):
        raise KernelError("legacy_refs must map names to events in the run")
    complete = all(repo.has(event_id) for event_id in events)
    parents: dict[str, list[str]] = {}
    positions = {event_id: index for index, event_id in enumerate(events)}
    for event_id in events:
        if not repo.has(event_id):
            continue
        event = repo.get(event_id)
        if event.object_type != "event":
            raise KernelError("run events must resolve to event objects")
        values = list(event.payload().get("parent_ids") or [])
        causal = list(event.payload().get("causal_ids") or [])
        if any(parent not in event_set for parent in values):
            raise KernelError(f"run event has a parent outside its event graph: {event_id}")
        if any(link not in event_set for link in causal):
            raise KernelError(f"run event has a causal link outside its event graph: {event_id}")
        if any(positions[link] >= positions[event_id] for link in [*values, *causal]):
            raise KernelError("run events must be in parent-before-child/dependency order")
        parents[event_id] = values
    if not complete:
        return  # Exact roots and tips require every shallow event envelope.
    expected_roots = {event_id for event_id, values in parents.items() if not values}
    expected_tips = event_set - {parent for values in parents.values() for parent in values}
    if set(payload.get("roots") or []) != expected_roots:
        raise KernelError("run roots do not match parentless events")
    if set(payload.get("tips") or []) != expected_tips:
        raise KernelError("run tips do not match event-graph leaves")


class PackedGraphView:
    """Read-through object view for validating a pack before installation."""

    def __init__(self, base: Any, packed: dict[str, bytes]):
        self.base = base
        self.packed = packed

    def has(self, oid: str) -> bool:
        return oid in self.packed or self.base.has(oid)

    def raw(self, oid: str) -> bytes:
        return self.packed.get(oid) or self.base.raw(oid)

    def get(self, oid: str) -> ObjectEnvelope:
        raw = self.packed.get(oid)
        envelope = ObjectEnvelope.decode(raw if raw is not None else self.base.raw(oid), oid)
        from opentine.kernel import validate_links

        validate_links(envelope)
        from opentine.repository._annotations import validate_annotation_chain

        validate_annotation_chain(self, envelope)
        validate_event_metrics(envelope)
        validate_run_graph(self, envelope)
        return envelope
