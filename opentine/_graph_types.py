"""Small value types and graph primitives used by compatibility runs."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from opentine._canon import _canonical_bytes


class StepKind(StrEnum):
    think = "think"
    tool = "tool"
    model = "model"
    done = "done"
    error = "error"


class RunStatus(StrEnum):
    running = "running"
    paused = "paused"
    completed = "completed"
    failed = "failed"


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


def _usage_value(name: str, value: Any) -> int | float:
    error = f"step usage.{name} must be a finite, non-negative safe number"
    if not isinstance(name, str) or not name:
        raise ValueError("step usage names must be non-empty strings")
    if isinstance(value, bool) or type(value) not in {int, float}:
        raise ValueError(error)
    if isinstance(value, int):
        if value < 0 or value > _MAX_SAFE_INTEGER:
            raise ValueError(error)
        return value
    if not math.isfinite(value) or value < 0:
        raise ValueError(error)
    if name in _TOKEN_USAGE and not value.is_integer():
        raise ValueError(f"step usage.{name} must be an integer token count")
    if value.is_integer() and value <= _MAX_SAFE_INTEGER:
        return int(value)
    if name in _TOKEN_USAGE:
        raise ValueError(error)
    return value


@dataclass(frozen=True)
class Step:
    id: str
    parent_ids: list[str]
    kind: StepKind
    inputs: dict[str, Any]
    outputs: dict[str, Any] = field(default_factory=dict)
    model_info: str = ""
    tool_info: dict[str, Any] = field(default_factory=dict)
    error: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    duration: float = 0.0
    cost: float = 0.0
    usage: dict[str, int | float] = field(default_factory=dict)
    billing: dict[str, Any] = field(default_factory=dict)
    v3_kind: str | None = None

    def __post_init__(self) -> None:
        for name, value in (("cost", self.cost), ("duration", self.duration)):
            if (
                isinstance(value, bool)
                or type(value) not in {int, float}
                or (isinstance(value, int) and value > _MAX_SAFE_INTEGER)
            ):
                raise ValueError(f"step {name} must be finite and non-negative")
            number = float(value)
            if not math.isfinite(number) or number < 0:
                raise ValueError(f"step {name} must be finite and non-negative")
            object.__setattr__(self, name, number)
        if not isinstance(self.usage, dict):
            raise ValueError("step usage must be a mapping")
        normalized_usage: dict[str, int | float] = {}
        for name, value in self.usage.items():
            normalized_usage[name] = _usage_value(name, value)
        object.__setattr__(self, "usage", normalized_usage)

    @property
    def parent_id(self) -> str | None:
        return self.parent_ids[-1] if self.parent_ids else None

    @property
    def short_id(self) -> str:
        return self.id[:12]


@dataclass
class Graph:
    steps: dict[str, Step] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)

    def add(self, step: Step) -> None:
        missing = [parent for parent in step.parent_ids if parent not in self.steps]
        if missing:
            rendered = ", ".join(short_id(item) for item in missing)
            raise ValueError(f"Unknown parent step(s): {rendered}")
        if step.id not in self.steps:
            self.order.append(step.id)
        self.steps[step.id] = step

    def ordered(self) -> list[Step]:
        return [self.steps[step_id] for step_id in self.order if step_id in self.steps]

    def roots(self) -> list[Step]:
        return [step for step in self.ordered() if not step.parent_ids]

    def children(self, step_id: str) -> list[Step]:
        resolved = self.resolve(step_id)
        return [step for step in self.ordered() if resolved in step.parent_ids]

    def resolve(self, ref: str) -> str:
        if ref in self.steps:
            return ref
        matches = [step_id for step_id in self.steps if step_id.startswith(ref)]
        if not matches:
            raise KeyError(f"Unknown step ref: {ref}")
        if len(matches) > 1:
            rendered = ", ".join(short_id(item) for item in matches)
            raise ValueError(f"Ambiguous step ref {ref}: {rendered}")
        return matches[0]

    def ancestors(self, step_ref: str) -> list[Step]:
        seen: set[str] = set()
        ordered: list[Step] = []
        stack = [(self.resolve(step_ref), False)]
        while stack:
            step_id, expanded = stack.pop()
            if step_id in seen:
                continue
            step = self.steps[step_id]
            if expanded:
                seen.add(step_id)
                ordered.append(step)
                continue
            stack.append((step_id, True))
            stack.extend((parent, False) for parent in reversed(step.parent_ids))
        return ordered

    def descendant_closure(self, step_ref: str) -> set[str]:
        root = self.resolve(step_ref)
        children: dict[str, list[str]] = {}
        for step in self.ordered():
            for parent in step.parent_ids:
                children.setdefault(parent, []).append(step.id)
        found: set[str] = set()
        pending = [root]
        while pending:
            step_id = pending.pop()
            if step_id in found:
                continue
            found.add(step_id)
            pending.extend(children.get(step_id, ()))
        return found


def step_id(
    kind: StepKind,
    inputs: dict[str, Any],
    parent_id: str | None = None,
    *,
    parent_ids: list[str] | None = None,
    outputs: dict[str, Any] | None = None,
    model_info: str = "",
    tool_info: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
) -> str:
    parents = list(parent_ids if parent_ids is not None else ([parent_id] if parent_id else []))
    payload = {
        "error": error or {},
        "inputs": inputs,
        "kind": kind.value,
        "model_info": model_info,
        "outputs": outputs or {},
        "parent_ids": parents,
        "tool_info": tool_info or {},
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def short_id(value: str) -> str:
    return value[:12]


def _normalize_tag(tag: str) -> str:
    return str(tag).strip().lower()


def _normalize_tags(tags: Any) -> list[str]:
    source = [tags] if isinstance(tags, str) else tags or []
    return sorted({_normalize_tag(tag) for tag in source if _normalize_tag(tag)})


@dataclass(frozen=True)
class FieldDelta:
    name: str
    before: Any
    after: Any
    changed_keys: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StepChange:
    step_a: Step
    step_b: Step
    fields: list[FieldDelta]


@dataclass
class RunDiff:
    common_ancestor: str | None
    only_a: list[Step]
    only_b: list[Step]
    changed: list[StepChange]


@dataclass(frozen=True)
class IntegrityResult:
    ok: bool
    algorithm: str | None
    expected: str | None
    actual: str | None
    reason: str
    draft: bool = False
