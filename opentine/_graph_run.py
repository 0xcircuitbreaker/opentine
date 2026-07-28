"""Construction and mutation of compatibility Run objects."""

from __future__ import annotations

import time
from decimal import Decimal, InvalidOperation
from typing import Any

from opentine._canon import FORMAT_VERSION, _jsonable
from opentine._graph_types import (
    Graph,
    RunStatus,
    Step,
    StepKind,
    _normalize_tag,
    _normalize_tags,
    _usage_value,
    step_id,
)
from opentine.billing._context import billing_context


def _usage(values: dict[str, int | float] | None) -> dict[str, int | float]:
    return {key: _usage_value(key, value) for key, value in (values or {}).items()}


def _step_cost_decimal(step: Step) -> Decimal:
    raw = step.billing.get("known_subtotal_usd", step.cost)
    try:
        amount = Decimal(str(raw))
        if not amount.is_finite() or amount < 0:
            raise ValueError("invalid known subtotal")
        return amount
    except (InvalidOperation, ValueError):
        return Decimal(str(step.cost))


class RunBase:
    def __init__(self, id: str | None = None, **kwargs: Any):
        self.run_id = kwargs.pop("run_id", id)
        self.status = kwargs.pop("status", RunStatus.running)
        self.graph = kwargs.pop("graph", Graph())
        self.refs = kwargs.pop("refs", {})
        self.transcript = kwargs.pop("transcript", [])
        self.manifest = kwargs.pop("manifest", {})
        self.policies = kwargs.pop("policies", {})
        self.cache = kwargs.pop("cache", {})
        self.metadata = kwargs.pop("metadata", {})
        self.created_at = kwargs.pop("created_at", 0.0)
        self.model_info = kwargs.pop("model_info", "")
        self.system_prompt = kwargs.pop("system_prompt", "")
        self.user_prompt = kwargs.pop("user_prompt", "")
        self.format_version = kwargs.pop("format_version", FORMAT_VERSION)
        tags = kwargs.pop("tags", None)
        if kwargs:
            raise TypeError(f"Unexpected Run field(s): {', '.join(kwargs)}")
        self.run_id = self.run_id or step_id(StepKind.model, {"created_at": time.time_ns()})
        self.status = RunStatus(self.status)
        if not isinstance(self.graph, Graph):
            from opentine._graph_serde import graph_from_dict

            self.graph = graph_from_dict(self.graph)
        self.refs = dict(self.refs)
        self.transcript = list(self.transcript)
        self.manifest = dict(self.manifest)
        self.policies = dict(self.policies)
        self.cache = dict(self.cache)
        self.metadata = dict(self.metadata)
        self.created_at = self.created_at or time.time()
        source_tags = tags if tags is not None else self.metadata.get("tags", [])
        self.tags = _normalize_tags(source_tags)
        self.refs.setdefault("main", self.graph.order[-1] if self.graph.order else "")

    @property
    def id(self) -> str:
        return self.run_id or ""

    @property
    def steps(self) -> list[Step]:
        return self.graph.ordered()

    def add_tag(self, tag: str) -> bool:
        normalized = _normalize_tag(tag)
        if not normalized or normalized in self.tags:
            return False
        self.tags = sorted([*self.tags, normalized])
        return True

    def remove_tag(self, tag: str) -> bool:
        normalized = _normalize_tag(tag)
        if normalized not in self.tags:
            return False
        self.tags = [item for item in self.tags if item != normalized]
        return True

    def has_tag(self, tag: str) -> bool:
        return _normalize_tag(tag) in self.tags

    def add_step(
        self,
        kind: StepKind,
        inputs: dict[str, Any],
        outputs: dict[str, Any] | None = None,
        parent_id: str | None = None,
        parent_ids: list[str] | None = None,
        duration: float = 0.0,
        cost: float = 0.0,
        model_info: str | None = None,
        tool_info: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
        ref: str = "main",
        usage: dict[str, int | float] | None = None,
        billing: dict[str, Any] | None = None,
    ) -> Step:
        parents = parent_ids if parent_ids is not None else ([parent_id] if parent_id else [])
        if not parents and self.refs.get(ref):
            parents = [self.refs[ref]]
        parents = [self.graph.resolve(parent) for parent in parents]
        resolved_model = model_info or self.model_info
        identifier = step_id(
            kind,
            inputs,
            parent_ids=parents,
            outputs=outputs,
            model_info=resolved_model,
            tool_info=tool_info,
            error=error,
        )
        step = Step(
            id=identifier,
            parent_ids=parents,
            kind=StepKind(kind),
            inputs=_jsonable(inputs),
            outputs=_jsonable(outputs or {}),
            model_info=resolved_model,
            tool_info=_jsonable(tool_info or {}),
            error=_jsonable(error or {}),
            timestamp=time.time(),
            duration=duration,
            cost=cost,
            usage=_usage(usage),
            billing=_jsonable(billing or {}),
        )
        self.graph.add(step)
        self.refs[ref] = identifier
        return step

    def get_step(self, step_id_value: str) -> Step | None:
        try:
            return self.graph.steps[self.graph.resolve(step_id_value)]
        except (KeyError, ValueError):
            return None

    def children(self, step_id_value: str) -> list[Step]:
        return self.graph.children(step_id_value)

    def root_steps(self) -> list[Step]:
        return self.graph.roots()

    def ancestors(self, step_id_value: str) -> list[Step]:
        return self.graph.ancestors(step_id_value)

    def common_ancestor(self, left: str, right: str) -> Step | None:
        left_ids = [step.id for step in self.ancestors(left)]
        right_ids = {step.id for step in self.ancestors(right)}
        for identifier in reversed(left_ids):
            if identifier in right_ids:
                return self.graph.steps[identifier]
        return None

    @property
    def total_cost(self) -> float:
        with billing_context():
            total = sum((_step_cost_decimal(step) for step in self.steps), Decimal("0"))
        return float(total)

    @property
    def total_duration(self) -> float:
        return sum(step.duration for step in self.steps)

    @property
    def total_tokens(self) -> int:
        dimensions = (
            "input",
            "output",
            "cache_read",
            "cache_write_5m",
            "cache_write_1h",
            "reasoning",
        )
        return sum(
            max(
                int(step.usage.get("total", 0)),
                sum(int(step.usage.get(name, 0)) for name in dimensions),
            )
            for step in self.steps
        )
