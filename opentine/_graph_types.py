"""Small value types and graph primitives used by compatibility runs."""

from __future__ import annotations

import hashlib
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

        def visit(step_id: str) -> None:
            if step_id in seen:
                return
            step = self.steps[step_id]
            for parent in step.parent_ids:
                visit(parent)
            seen.add(step_id)
            ordered.append(step)

        visit(self.resolve(step_ref))
        return ordered

    def descendant_closure(self, step_ref: str) -> set[str]:
        root = self.resolve(step_ref)
        found = {root}
        changed = True
        while changed:
            changed = False
            for step in self.ordered():
                if step.id not in found and any(parent in found for parent in step.parent_ids):
                    found.add(step.id)
                    changed = True
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
