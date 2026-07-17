"""Normalized trace records shared by native and imported agent runs."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

TraceKind = Literal["model", "tool", "human", "policy", "approval", "subagent", "error"]
TRACE_KINDS = frozenset({"model", "tool", "human", "policy", "approval", "subagent", "error"})
TOKEN_USAGE = frozenset(
    {"input", "output", "cache_read", "cache_write_5m", "cache_write_1h", "reasoning", "total"}
)


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
        try:
            timestamp = float(self.timestamp)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("trace timestamp must be finite") from exc
        if isinstance(self.timestamp, bool) or not math.isfinite(timestamp):
            raise ValueError("trace timestamp must be finite")
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
        billed = self.billing.get("known_subtotal_usd") if isinstance(self.billing, dict) else None
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
        if not isinstance(self.usage, dict):
            raise ValueError("trace usage must be a mapping")
        for name, value in self.usage.items():
            valid = isinstance(name, str) and type(value) in {int, float}
            number = float(value) if valid else float("nan")
            if name in TOKEN_USAGE:
                valid = valid and number.is_integer() and number <= (1 << 53) - 1
            if not valid or not math.isfinite(number) or number < 0:
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
