"""Normalized trace records shared by native and imported agent runs."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from opentine._jsonsafe import json_safe
from opentine.kernel import KernelError
from opentine.repository._run_graph import _meter as _store_meter

TraceKind = Literal["model", "tool", "human", "policy", "approval", "subagent", "error"]
TRACE_KINDS = frozenset({"model", "tool", "human", "policy", "approval", "subagent", "error"})
TOKEN_USAGE = frozenset(
    {"input", "output", "cache_read", "cache_write_5m", "cache_write_1h", "reasoning", "total"}
)
_MAX_SAFE_INTEGER = (1 << 53) - 1


def _stored_metric(value: Any, message: str, *, nonnegative: bool = True) -> None:
    """Reject metric values the event store would refuse once stored.

    put_trace_event persists json_safe(value) and the repository judges that
    stored form with its _meter gate — running the same gate on the same form
    here means a TraceEvent that constructs can always be appended, instead of
    crashing an append/import with a KernelError from deep inside repo.put.
    """
    try:
        _store_meter(json_safe(value), "trace metric", nonnegative=nonnegative)
    except KernelError as exc:
        raise ValueError(message) from exc


@dataclass(frozen=True)
class TraceEvent:
    kind: TraceKind
    timestamp: float
    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    causal_span_ids: tuple[str, ...] = ()
    actor: str = ""
    model: str = ""
    cost: float | str | None = None
    duration: float = 0
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    usage: dict[str, Any] = field(default_factory=dict)
    billing: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in TRACE_KINDS:
            raise ValueError(f"invalid trace event kind: {self.kind!r}")
        for name in ("inputs", "outputs", "usage", "billing", "attributes"):
            value = getattr(self, name)
            if not isinstance(value, dict):
                raise ValueError(f"trace {name} must be a mapping")
            object.__setattr__(self, name, dict(value))
        try:
            timestamp = float(self.timestamp)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("trace timestamp must be finite") from exc
        if isinstance(self.timestamp, bool) or not math.isfinite(timestamp):
            raise ValueError("trace timestamp must be finite")
        _stored_metric(self.timestamp, "trace timestamp must be finite", nonnegative=False)
        try:
            if isinstance(self.duration, str) and len(self.duration) > 128:
                raise ValueError
            duration = float(self.duration)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("trace duration must be finite and non-negative") from exc
        if isinstance(self.duration, bool) or not math.isfinite(duration):
            raise ValueError("trace duration must be finite and non-negative")
        if duration < 0:
            raise ValueError("trace duration must be finite and non-negative")
        _stored_metric(self.duration, "trace duration must be finite and non-negative")
        billed = self.billing.get("known_subtotal_usd")
        values = [self.cost, billed]
        for value in (item for item in values if item is not None):
            try:
                if isinstance(value, str) and len(value) > 128:
                    raise ValueError
                amount = Decimal(str(value))
            except (InvalidOperation, ValueError) as exc:
                raise ValueError("trace cost must be finite and non-negative") from exc
            if isinstance(value, bool) or not amount.is_finite() or amount < 0:
                raise ValueError("trace cost must be finite and non-negative")
            _stored_metric(value, "trace cost must be finite and non-negative")
        for name, value in self.usage.items():
            integer = type(value) is int
            floating = type(value) is float
            valid = isinstance(name, str) and (integer or floating)
            valid = valid and value >= 0 and (integer or math.isfinite(value))
            # json_safe stringifies ints above 2**53-1 and the event store then
            # rejects the stored string as non-numeric, so every dimension is
            # bounded — not just token counts.
            valid = valid and (floating or value <= _MAX_SAFE_INTEGER)
            if name in TOKEN_USAGE:
                valid = valid and (integer or value.is_integer()) and value <= _MAX_SAFE_INTEGER
            if not valid:
                raise ValueError(f"trace usage.{name} must be finite and non-negative")

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "attributes": self.attributes,
            "billing": self.billing,
            "causal_span_ids": list(self.causal_span_ids),
            "cost": self.cost,
            "duration": self.duration,
            "inputs": self.inputs,
            "kind": self.kind,
            "model": self.model,
            "outputs": self.outputs,
            "parent_span_id": self.parent_span_id,
            "span_id": self.span_id,
            "timestamp": self.timestamp,
            "trace_id": self.trace_id,
            "usage": self.usage,
        }
