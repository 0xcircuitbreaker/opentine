"""Normalized trace records shared by native and imported agent runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

TraceKind = Literal["model", "tool", "human", "policy", "approval", "subagent", "error"]


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
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    usage: dict[str, int | float] = field(default_factory=dict)
    billing: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "attributes": self.attributes,
            "billing": self.billing,
            "causal_span_ids": list(self.causal_span_ids),
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
