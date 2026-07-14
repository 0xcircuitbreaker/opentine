"""Aggregation, budgets, forks, and semantic comparison for compatibility runs."""

from __future__ import annotations

from opentine._graph_types import Graph, RunStatus, StepKind, step_id
from opentine.budget import Budget, CostBreakdown


class RunAnalysisMixin:
    def cost_breakdown(self) -> CostBreakdown:
        by_model: dict[str, float] = {}
        by_kind: dict[str, float] = {}
        input_tokens = output_tokens = 0
        for step in self.steps:
            by_model[step.model_info] = by_model.get(step.model_info, 0.0) + step.cost
            by_kind[step.kind.value] = by_kind.get(step.kind.value, 0.0) + step.cost
            input_tokens += sum(
                int(step.usage.get(name, 0))
                for name in ("input", "cache_read", "cache_write_5m", "cache_write_1h")
            )
            output_tokens += int(step.usage.get("output", 0)) + int(step.usage.get("reasoning", 0))
        by_ref: dict[str, float] = {}
        for ref, tip in self.refs.items():
            if not tip:
                continue
            try:
                ancestors = self.ancestors(tip)
            except (KeyError, ValueError):
                continue
            by_ref[ref] = sum(step.cost for step in ancestors)
        return CostBreakdown(
            total_cost=self.total_cost,
            total_tokens=input_tokens + output_tokens,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            by_model=by_model,
            by_kind=by_kind,
            by_ref=by_ref,
        )

    def set_budget(
        self,
        *,
        max_cost: float | None = None,
        max_steps: int | None = None,
        max_duration: float | None = None,
        max_usage: int | None = None,
        on_breach: str = "stop",
        strict_cost: bool = False,
    ) -> Budget:
        budget = Budget(
            max_cost=max_cost,
            max_steps=max_steps,
            max_duration=max_duration,
            max_usage=max_usage,
            on_breach=on_breach,
            strict_cost=strict_cost,
        )
        self.manifest["budget"] = budget.to_dict()
        return budget

    def budget(self) -> Budget | None:
        raw = self.manifest.get("budget")
        return Budget.from_dict(raw) if isinstance(raw, dict) and raw else None

    def fork(
        self,
        from_step_id: str,
        new_run_id: str | None = None,
        branch: str = "main",
    ):
        fork_point = self.graph.resolve(from_step_id)
        graph = Graph()
        for step in self.ancestors(fork_point):
            graph.add(step)
        run_id = new_run_id or step_id(StepKind.model, {"fork": self.id, "from": fork_point})
        metadata = {key: value for key, value in self.metadata.items() if key != "tags"}
        metadata.update({"forked_from": self.id, "fork_point": fork_point})
        return self.__class__(
            id=run_id,
            status=RunStatus.running,
            graph=graph,
            refs={branch: fork_point, "fork_point": fork_point},
            transcript=[item for item in self.transcript if item.get("step_id") in graph.steps],
            manifest=dict(self.manifest),
            policies=dict(self.policies),
            metadata=metadata,
            model_info=self.model_info,
            system_prompt=self.system_prompt,
            user_prompt=self.user_prompt,
            tags=[],
        )

    def diff(self, other):
        from opentine._graph_diff import diff_runs

        return diff_runs(self, other)
