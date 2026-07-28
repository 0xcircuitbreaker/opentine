"""Cost/usage budgets and aggregation primitives.

This module deals only in plain numbers (cost, token usage, step count, wall
duration) so it never imports ``graph`` — enforcement code passes the running
totals in. Budgets persist at ``manifest.budget`` (inside the integrity digest,
so a tampered limit is detectable), while the derived ``budget_state`` lives in
metadata (outside the digest) and is never authoritative.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from decimal import Decimal

_DIMENSIONS = ("max_cost", "max_steps", "max_duration", "max_usage")


class BudgetExceeded(RuntimeError):
    """Raised when an ``on_breach="raise"`` budget is exceeded."""

    def __init__(self, breach: BudgetBreach, run=None):
        self.breach = breach
        self.run = run  # the partially-recorded run, so callers can still save it
        super().__init__(str(breach))


@dataclass(frozen=True)
class BudgetBreach:
    dimension: str  # "cost" | "usage" | "steps" | "duration"
    limit: float
    incurred: float

    def __str__(self) -> str:
        if self.dimension == "cost_completeness":
            return "budget stopped: model price is incomplete or unknown"
        return f"budget exceeded: {self.dimension} {self.incurred} > limit {self.limit}"

    def to_dict(self) -> dict:
        return {"dimension": self.dimension, "limit": self.limit, "incurred": self.incurred}


@dataclass(frozen=True)
class Budget:
    max_cost: float | None = None
    max_steps: int | None = None
    max_duration: float | None = None
    #: total tokens (input + output). Named "usage" not "tokens" on purpose: the
    #: redaction layer blanks any serialized key containing "token".
    max_usage: int | None = None
    on_breach: str = "stop"  # "stop" -> mark failed and halt; "raise" -> BudgetExceeded
    strict_cost: bool = False  # halt before another call after incomplete billing

    def __post_init__(self) -> None:
        if self.on_breach not in ("stop", "raise"):
            raise ValueError(f"on_breach must be 'stop' or 'raise', got {self.on_breach!r}")
        for name in _DIMENSIONS:
            value = getattr(self, name)
            if value is None:
                continue
            integer = name in {"max_steps", "max_usage"}
            try:
                number = float(value)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError(f"{name} must be finite and > 0, got {value!r}") from exc
            if (
                isinstance(value, bool)
                or not math.isfinite(number)
                or number <= 0
                or (integer and type(value) is not int)
            ):
                expected = "a positive integer" if integer else "finite and > 0"
                raise ValueError(f"{name} must be {expected}, got {value!r}")

    def check(self, *, cost: float, usage: int, steps: int, duration: float) -> BudgetBreach | None:
        """Return the first breached dimension, or None if within budget."""
        if self.max_cost is not None and Decimal(str(cost)) > Decimal(str(self.max_cost)):
            return BudgetBreach("cost", self.max_cost, cost)
        if self.max_usage is not None and usage > self.max_usage:
            return BudgetBreach("usage", self.max_usage, usage)
        if self.max_steps is not None and steps > self.max_steps:
            return BudgetBreach("steps", self.max_steps, steps)
        if self.max_duration is not None and duration > self.max_duration:
            return BudgetBreach("duration", self.max_duration, duration)
        return None

    def to_dict(self) -> dict:
        data: dict[str, float | int | str] = {"on_breach": self.on_breach}
        for name in _DIMENSIONS:
            value = getattr(self, name)
            if value is not None:
                data[name] = value
        if self.strict_cost:
            data["strict_cost"] = True
        return data

    @classmethod
    def from_dict(cls, data: dict) -> Budget:
        return cls(
            max_cost=data.get("max_cost"),
            max_steps=data.get("max_steps"),
            max_duration=data.get("max_duration"),
            max_usage=data.get("max_usage"),
            on_breach=data.get("on_breach", "stop"),
            strict_cost=bool(data.get("strict_cost", False)),
        )


@dataclass(frozen=True)
class CostBreakdown:
    total_cost: float
    total_tokens: int
    input_tokens: int
    output_tokens: int
    by_model: dict[str, float] = field(default_factory=dict)
    by_kind: dict[str, float] = field(default_factory=dict)
    by_ref: dict[str, float] = field(default_factory=dict)
