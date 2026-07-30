"""Aggregation, budgets, forks, and semantic comparison for compatibility runs."""

from __future__ import annotations

import copy
from decimal import Decimal

from opentine._graph_pricing import _slice_pricing
from opentine._graph_run import _step_cost_decimal
from opentine._graph_types import Graph, RunStatus, StepKind, step_id
from opentine.billing._context import billing_context
from opentine.budget import Budget, CostBreakdown


def _causal_transcript(transcript: list[dict], retained: set[str], fork_point: str) -> list[dict]:
    """Associate unscoped human turns with the next content-addressed event."""
    result: list[dict] = []
    pending: list[dict] = []
    scoped = False
    last_retained = False
    for item in transcript:
        # Loading tolerates non-dict items, so fork treats them as unscoped turns.
        step = item.get("step_id") if isinstance(item, dict) else None
        if not isinstance(step, str):
            pending.append(item)
            continue
        scoped = True
        last_retained = step in retained
        if last_retained:
            result.extend(pending)
            result.append(item)
        pending = []
        if step == fork_point:
            return result
    # Hand-authored/legacy transcripts without event IDs have no finer causal slice.
    if not scoped:
        return list(transcript)
    if pending and last_retained:
        result.extend(pending)
    return result


class RunAnalysisMixin:
    def cost_breakdown(self) -> CostBreakdown:
        by_model_decimal: dict[str, Decimal] = {}
        by_kind_decimal: dict[str, Decimal] = {}
        input_tokens = output_tokens = 0
        with billing_context():
            for step in self.steps:
                cost = _step_cost_decimal(step)
                by_model_decimal[step.model_info] = (
                    by_model_decimal.get(step.model_info, Decimal("0")) + cost
                )
                by_kind_decimal[step.kind.value] = (
                    by_kind_decimal.get(step.kind.value, Decimal("0")) + cost
                )
                input_tokens += sum(
                    int(step.usage.get(name, 0))
                    for name in ("input", "cache_read", "cache_write_5m", "cache_write_1h")
                )
                output_tokens += int(step.usage.get("output", 0)) + int(
                    step.usage.get("reasoning", 0)
                )
        by_ref: dict[str, float] = {}
        for ref, tip in self.refs.items():
            if not tip:
                continue
            try:
                ancestors = self.ancestors(tip)
            except (KeyError, ValueError):
                continue
            with billing_context():
                by_ref[ref] = float(
                    sum((_step_cost_decimal(step) for step in ancestors), Decimal("0"))
                )
        return CostBreakdown(
            total_cost=self.total_cost,
            total_tokens=input_tokens + output_tokens,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            by_model={key: float(value) for key, value in by_model_decimal.items()},
            by_kind={key: float(value) for key, value in by_kind_decimal.items()},
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
        causal = getattr(self, "_v3_causal_ids", {})
        retained: set[str] = set()

        pending = [fork_point]
        while pending:
            step_id_value = pending.pop()
            if step_id_value in retained:
                continue
            retained.add(step_id_value)
            step = self.graph.steps[step_id_value]
            pending.extend([*step.parent_ids, *(causal.get(step_id_value) or [])])
        graph = Graph()
        for step in self.steps:
            if step.id in retained:
                graph.add(copy.deepcopy(step))
        run_id = new_run_id or step_id(StepKind.model, {"fork": self.id, "from": fork_point})
        metadata = copy.deepcopy(
            {
                key: value
                for key, value in self.metadata.items()
                if key not in {"budget_state", "tags", "warnings"}
            }
        )
        metadata.update({"forked_from": self.id, "fork_point": fork_point})
        manifest = copy.deepcopy(self.manifest)
        manifest.pop("resume_history", None)
        _slice_pricing(manifest, retained)
        model = next(
            (
                step.model_info
                for step in reversed(self.steps)
                if step.id in retained and step.model_info
            ),
            "",
        )
        if isinstance(manifest.get("model"), dict):
            manifest["model"] = {**manifest["model"]}
            if model:
                manifest["model"]["name"] = model
            else:
                manifest["model"].pop("name", None)
        forked = self.__class__(
            id=run_id,
            status=RunStatus.running,
            graph=graph,
            refs={branch: fork_point, "fork_point": fork_point},
            transcript=_causal_transcript(self.transcript, set(graph.steps), fork_point),
            manifest=manifest,
            policies=copy.deepcopy(self.policies),
            metadata=metadata,
            model_info=model,
            system_prompt=self.system_prompt,
            user_prompt=self.user_prompt,
            tags=[],
        )
        forked._v3_causal_ids = {
            step: list(values) for step, values in causal.items() if step in retained
        }
        origin = getattr(self, "_v3_payload", None)
        origin_id = getattr(self, "_v3_run_id", None)
        if isinstance(origin, dict) and isinstance(origin_id, str):
            source_manifests = origin.get("manifests") or {}
            forked._v3_fork_base = {
                "manifests": {
                    name: oid
                    for name, oid in source_manifests.items()
                    if name in {"budget", "code", "environment", "pricing"}
                },
                **({"session_id": origin["session_id"]} if "session_id" in origin else {}),
            }
            forked._v3_source_payload = origin
            forked._v3_source_run_id = origin_id
        return forked

    def diff(self, other):
        from opentine._graph_diff import diff_runs

        return diff_runs(self, other)
