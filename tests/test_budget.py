"""Cost aggregation + budget enforcement coverage."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from opentine import Budget, BudgetExceeded, Run, StepKind
from opentine.core import RunStatus, step_id
from opentine.runtime import Agent

FIXTURES = Path(__file__).parent / "fixtures"


# --- usage plumbing & content addressing ------------------------------------


def test_usage_does_not_change_step_id():
    run_a = Run(id="a")
    a = run_a.add_step(StepKind.done, {"text": "hi"}, cost=1.0, usage={"input": 10, "output": 5})
    bare = step_id(StepKind.done, {"text": "hi"})
    assert a.id == bare  # usage (like cost) is excluded from the content hash
    assert a.usage == {"input": 10, "output": 5}


def test_usage_absent_when_empty(tmp_path: Path):
    run = Run(id="x")
    run.add_step(StepKind.done, {"text": "hi"})
    p = run.save(tmp_path / "a.tine")
    step = next(iter(json.loads(p.read_text())["graph"]["steps"].values()))
    assert "usage" not in step


def test_redact_roundtrip_preserves_usage_and_budget_numerics(tmp_path: Path):
    # Headline regression: the keys 'usage'/'max_usage' must survive redaction.
    # (A naive 'tokens'/'max_tokens' key would be blanked by _redact.)
    run = Run(id="x")
    run.set_budget(max_cost=1.5, max_usage=2000, max_steps=10)
    run.add_step(StepKind.done, {"text": "hi"}, cost=0.5, usage={"input": 100, "output": 40})
    p = run.save(tmp_path / "a.tine")

    data = json.loads(p.read_text())
    step = next(iter(data["graph"]["steps"].values()))
    assert step["usage"] == {"input": 100, "output": 40}
    assert data["manifest"]["budget"]["max_usage"] == 2000
    assert data["manifest"]["budget"]["max_cost"] == 1.5

    loaded = Run.load(p)
    assert loaded.total_tokens == 140
    assert loaded.budget().max_usage == 2000


# --- aggregation ------------------------------------------------------------


def test_cost_breakdown_groups_and_sums():
    run = Run(id="x", model_info="m1")
    run.add_step(StepKind.think, {"text": "a"}, cost=0.10, usage={"input": 10, "output": 2})
    run.add_step(StepKind.tool, {"name": "t"}, cost=0.00)
    run.add_step(StepKind.done, {"text": "b"}, cost=0.20, usage={"input": 5, "output": 3})

    bd = run.cost_breakdown()
    assert abs(bd.total_cost - 0.30) < 1e-9
    assert bd.total_tokens == 20
    assert bd.input_tokens == 15 and bd.output_tokens == 5
    assert abs(bd.by_model["m1"] - 0.30) < 1e-9
    assert abs(bd.by_kind["think"] - 0.10) < 1e-9
    assert abs(bd.by_kind["done"] - 0.20) < 1e-9
    # by_ref sums the cost of the main branch tip's ancestors
    assert abs(bd.by_ref["main"] - 0.30) < 1e-9


def test_cost_breakdown_on_empty_run_does_not_raise():
    bd = Run(id="empty").cost_breakdown()  # refs['main'] == '' must be skipped
    assert bd.total_cost == 0.0
    assert bd.by_ref == {}


def test_graceful_degrade_without_usage():
    run = Run(id="x")
    run.add_step(StepKind.done, {"text": "hi"}, cost=0.5)  # no usage
    assert run.total_tokens == 0
    assert run.cost_breakdown().total_cost == 0.5


# --- budget object ----------------------------------------------------------


def test_budget_rejects_nonpositive_limits():
    with pytest.raises(ValueError):
        Budget(max_cost=0)
    with pytest.raises(ValueError):
        Budget(max_steps=-1)
    with pytest.raises(ValueError):
        Budget(on_breach="explode")


def test_v1_run_has_no_budget():
    run = Run.load(FIXTURES / "golden_v1.tine")
    assert run.budget() is None


def test_budget_in_manifest_is_tamper_evident(tmp_path: Path):
    run = Run(id="x")
    run.set_budget(max_cost=1.0)
    run.add_step(StepKind.done, {"text": "hi"})
    p = run.save(tmp_path / "a.tine")
    assert Run.verify_integrity(p).ok

    # manifest.budget is inside the digest -> editing the limit breaks verify
    data = json.loads(p.read_text())
    data["manifest"]["budget"]["max_cost"] = 9999
    p.write_text(json.dumps(data), encoding="utf-8")
    assert not Run.verify_integrity(p).ok


def test_budget_state_is_outside_the_digest(tmp_path: Path):
    run = Run(id="y")
    run.set_budget(max_cost=1.0)
    run.add_step(StepKind.done, {"text": "hi"})
    p = run.save(tmp_path / "b.tine")

    # metadata.budget_state is derived/mutable and outside the digest
    data = json.loads(p.read_text())
    data["metadata"]["budget_state"] = {"breached": True, "dimension": "cost"}
    p.write_text(json.dumps(data), encoding="utf-8")
    assert Run.verify_integrity(p).ok


# --- enforcement in the agent loop ------------------------------------------


class LoopingModel:
    """Always emits a tool call (so the loop continues) with a fixed cost."""

    def __init__(self, cost=1.0, usage=None):
        self._cost = cost
        self._usage = usage or {"input": 10, "output": 5}

    name = "loop-model"
    supports_tools = True
    supports_thinking = False

    async def complete(self, messages, tools=None, system=None, temperature=0.0):
        return {
            "text": "step",
            "tool_calls": [{"name": "noop", "arguments": {}}],
            "cost": self._cost,
            "usage": self._usage,
        }

    async def stream(self, *a, **k) -> AsyncIterator[dict[str, Any]]:
        yield await self.complete(*a, **k)


def _noop() -> str:
    """Do nothing."""
    return "ok"


def test_budget_stop_mode_records_error_and_marks_failed():
    agent = Agent(
        model=LoopingModel(cost=1.0),
        tools=[_noop],
        max_steps=20,
        budget=Budget(max_cost=0.5, on_breach="stop"),
    )
    run = agent.run_sync("go")
    assert run.status == RunStatus.failed
    assert any(s.kind == StepKind.error for s in run.steps)
    state = run.metadata["budget_state"]
    assert state["breached"] is True and state["dimension"] == "cost"
    # the loop halted near the budget, not at max_steps
    assert run.total_cost <= 2.0


def test_budget_raise_mode_raises_with_recoverable_run():
    agent = Agent(
        model=LoopingModel(cost=1.0),
        tools=[_noop],
        max_steps=20,
        budget=Budget(max_cost=0.5, on_breach="raise"),
    )
    with pytest.raises(BudgetExceeded) as excinfo:
        agent.run_sync("go")
    # the partially-recorded run is attached so it can still be saved
    assert excinfo.value.run is not None
    assert excinfo.value.run.status == RunStatus.failed
    assert excinfo.value.breach.dimension == "cost"


def test_no_budget_runs_normally():
    agent = Agent(model=LoopingModel(cost=1.0), tools=[_noop], max_steps=3)
    run = agent.run_sync("go")
    # hits max_steps (no budget), not a budget breach
    assert run.status == RunStatus.failed
    assert run.metadata.get("budget_state") is None


def test_strict_cost_budget_stops_before_call_after_unknown_price():
    model = LoopingModel(cost=0)
    model.calls = 0

    async def unknown_complete(messages, tools=None, system=None, temperature=0.0):
        model.calls += 1
        response = await LoopingModel.complete(
            model, messages, tools=tools, system=system, temperature=temperature
        )
        response["billing"] = {
            "status": "unknown",
            "amount_usd": None,
            "known_subtotal_usd": "0",
            "warnings": ["price is unknown"],
        }
        return response

    model.complete = unknown_complete
    run = Agent(
        model=model,
        tools=[_noop],
        max_steps=20,
        budget=Budget(max_cost=1, strict_cost=True),
    ).run_sync("go")
    assert model.calls == 1
    assert run.status == RunStatus.failed
    assert run.metadata["budget_state"]["dimension"] == "cost_completeness"


# --- harness budget enforcement ---------------------------------------------


class _CostHarness:
    name = "fake"
    model_info = "fake"
    supports_resume = False

    def execute(self, task, context=None, step_callback=None):
        from opentine.harnesses.base import HarnessStep

        for i in range(10):
            step_callback(HarnessStep(kind=StepKind.think, inputs={"text": f"s{i}"}, cost=1.0))
        return {"ok": True}


def _harness_with_budget(on_breach: str):
    from opentine.harnesses.base import OpentineHarness

    run = Run(id="h")
    run.set_budget(max_cost=2.5, on_breach=on_breach)
    return OpentineHarness(_CostHarness(), run=run)


def test_harness_budget_stop_returns_failed_run_without_raising():
    wrapped = _harness_with_budget("stop")
    out = wrapped.run_sync("go")  # must NOT raise
    assert out.status == RunStatus.failed
    assert out.metadata["budget_state"]["breached"] is True
    assert any(s.kind == StepKind.error for s in out.steps)
    # only one budget error step (no double-record)
    assert sum(1 for s in out.steps if s.kind == StepKind.error) == 1


def test_harness_budget_raise_propagates():
    wrapped = _harness_with_budget("raise")
    with pytest.raises(BudgetExceeded):
        wrapped.run_sync("go")
