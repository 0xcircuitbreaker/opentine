"""Tests for opentine core: Step, Run, fork, serialization, Agent."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from opentine.core import Agent, Run, RunStatus, StepKind, step_id, tool_schema

# --- Step -------------------------------------------------------------------


class TestStep:
    def test_content_addressing_deterministic(self):
        a = step_id(StepKind.think, {"text": "hello"})
        b = step_id(StepKind.think, {"text": "hello"})
        assert a == b

    def test_content_addressing_differs_on_input(self):
        a = step_id(StepKind.think, {"text": "hello"})
        b = step_id(StepKind.think, {"text": "world"})
        assert a != b

    def test_content_addressing_differs_on_kind(self):
        a = step_id(StepKind.think, {"text": "hello"})
        b = step_id(StepKind.tool, {"text": "hello"})
        assert a != b

    def test_content_addressing_differs_on_parent(self):
        a = step_id(StepKind.think, {"text": "hello"}, parent_id="abc")
        b = step_id(StepKind.think, {"text": "hello"}, parent_id="def")
        assert a != b

    def test_step_id_is_12_chars(self):
        sid = step_id(StepKind.think, {"text": "hello"})
        assert len(sid) == 12


# --- Run tree operations ----------------------------------------------------


class TestRun:
    def _make_run(self) -> Run:
        run = Run(id="test_run")
        run.add_step(StepKind.think, {"text": "thinking..."})
        run.add_step(StepKind.tool, {"name": "search", "arguments": {"q": "test"}})
        run.add_step(StepKind.think, {"text": "processing..."})
        run.add_step(StepKind.done, {"text": "done!"})
        return run

    def test_add_step_builds_chain(self):
        run = self._make_run()
        assert len(run.steps) == 4
        for i in range(1, len(run.steps)):
            assert run.steps[i].parent_id == run.steps[i - 1].id

    def test_root_steps(self):
        run = self._make_run()
        roots = run.root_steps()
        assert len(roots) == 1
        assert roots[0].id == run.steps[0].id

    def test_get_step(self):
        run = self._make_run()
        s = run.get_step(run.steps[2].id)
        assert s is not None
        assert s.kind == StepKind.think

    def test_get_step_missing(self):
        run = self._make_run()
        assert run.get_step("nonexistent") is None

    def test_children(self):
        run = self._make_run()
        kids = run.children(run.steps[0].id)
        assert len(kids) == 1
        assert kids[0].id == run.steps[1].id

    def test_ancestors(self):
        run = self._make_run()
        anc = run.ancestors(run.steps[3].id)
        assert len(anc) == 4
        assert anc[0].id == run.steps[0].id
        assert anc[-1].id == run.steps[3].id

    def test_total_cost(self):
        run = Run(id="cost_test")
        run.add_step(StepKind.think, {"text": "a"}, cost=0.001)
        run.add_step(StepKind.done, {"text": "b"}, cost=0.002)
        assert abs(run.total_cost - 0.003) < 1e-9

    def test_total_duration(self):
        run = Run(id="dur_test")
        run.add_step(StepKind.think, {"text": "a"}, duration=1.0)
        run.add_step(StepKind.done, {"text": "b"}, duration=2.0)
        assert abs(run.total_duration - 3.0) < 1e-9


# --- Fork -------------------------------------------------------------------


class TestFork:
    def test_fork_preserves_ancestors(self):
        run = Run(id="original")
        run.add_step(StepKind.think, {"text": "step1"})
        run.add_step(StepKind.tool, {"name": "t", "arguments": {}})
        run.add_step(StepKind.think, {"text": "step3"})
        run.add_step(StepKind.done, {"text": "step4"})

        forked = run.fork(run.steps[1].id, new_run_id="forked")
        assert forked.id == "forked"
        assert len(forked.steps) == 2
        assert forked.steps[0].id == run.steps[0].id
        assert forked.steps[1].id == run.steps[1].id
        assert forked.status == RunStatus.running

    def test_fork_metadata(self):
        run = Run(id="orig")
        run.add_step(StepKind.think, {"text": "x"})
        forked = run.fork(run.steps[0].id)
        assert forked.metadata["forked_from"] == "orig"
        assert forked.metadata["fork_point"] == run.steps[0].id

    def test_fork_inherits_prompts(self):
        run = Run(id="orig", system_prompt="sys", user_prompt="user")
        run.add_step(StepKind.think, {"text": "x"})
        forked = run.fork(run.steps[0].id)
        assert forked.system_prompt == "sys"
        assert forked.user_prompt == "user"


# --- Serialization ----------------------------------------------------------


class TestSerialization:
    def test_save_load_roundtrip(self, tmp_path: Path):
        run = Run(id="serial_test", model_info="test-model")
        run.add_step(StepKind.think, {"text": "hello"}, cost=0.01)
        run.add_step(StepKind.done, {"text": "bye"})

        path = run.save(tmp_path / "test.tine")
        loaded = Run.load(path)
        assert loaded.id == "serial_test"
        assert len(loaded.steps) == 2
        assert loaded.steps[0].cost == 0.01
        assert loaded.model_info == "test-model"

    def test_pause_resume(self, tmp_path: Path):
        run = Run(id="pause_test")
        run.add_step(StepKind.think, {"text": "wip"})

        path = run.pause(tmp_path / "paused.tine")
        assert run.status == RunStatus.paused

        resumed = Run.resume(path)
        assert resumed.status == RunStatus.running
        assert resumed.id == "pause_test"
        assert len(resumed.steps) == 1

    def test_tine_file_is_valid_json(self, tmp_path: Path):
        run = Run(id="json_test")
        run.add_step(StepKind.done, {"text": "ok"})
        path = run.save(tmp_path / "check.tine")
        data = json.loads(path.read_text())
        assert data["id"] == "json_test"


# --- Tool schema ------------------------------------------------------------


class TestToolSchema:
    def test_basic_function(self):
        def greet(name: str, loud: bool = False) -> str:
            """Say hello to someone."""
            return f"Hello, {name}!"

        schema = tool_schema(greet)
        assert schema["name"] == "greet"
        assert schema["description"] == "Say hello to someone."
        assert "name" in schema["input_schema"]["properties"]
        assert schema["input_schema"]["required"] == ["name"]

    def test_no_docstring(self):
        def bare(x: int):
            pass

        schema = tool_schema(bare)
        assert schema["description"] == ""


# --- Agent with mock model --------------------------------------------------


class MockModel:
    def __init__(self, responses: list[dict[str, Any]]):
        self._responses = list(responses)
        self._idx = 0

    @property
    def name(self) -> str:
        return "mock-model"

    @property
    def supports_tools(self) -> bool:
        return True

    @property
    def supports_thinking(self) -> bool:
        return False

    async def complete(self, messages, tools=None, system=None, temperature=0.0):
        resp = self._responses[self._idx]
        self._idx = min(self._idx + 1, len(self._responses) - 1)
        return resp

    async def stream(
        self, messages, tools=None, system=None, temperature=0.0
    ) -> AsyncIterator[dict[str, Any]]:
        yield await self.complete(messages, tools, system, temperature)


class TestAgent:
    def test_simple_completion(self):
        model = MockModel([{"text": "The answer is 42.", "tool_calls": []}])
        agent = Agent(model=model)
        run = agent.run_sync("What is the answer?")
        assert run.status == RunStatus.completed
        assert len(run.steps) == 1
        assert run.steps[0].kind == StepKind.done

    def test_tool_call_flow(self):
        def add(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        model = MockModel(
            [
                {
                    "text": "Let me add those.",
                    "tool_calls": [{"name": "add", "arguments": {"a": 2, "b": 3}}],
                },
                {"text": "The sum is 5.", "tool_calls": []},
            ]
        )
        agent = Agent(model=model, tools=[add])
        run = agent.run_sync("Add 2 and 3")
        assert run.status == RunStatus.completed
        assert any(s.kind == StepKind.tool for s in run.steps)
        assert any(s.kind == StepKind.done for s in run.steps)

    def test_max_steps_exceeded(self):
        model = MockModel(
            [
                {"text": "loop", "tool_calls": [{"name": "noop", "arguments": {}}]},
            ]
        )

        def noop() -> str:
            """Do nothing."""
            return "ok"

        agent = Agent(model=model, tools=[noop], max_steps=3)
        run = agent.run_sync("Loop forever")
        assert run.status == RunStatus.failed
        assert any(s.kind == StepKind.error for s in run.steps)

    def test_tool_error_handling(self):
        def explode() -> str:
            """Always fails."""
            raise ValueError("boom")

        model = MockModel(
            [
                {"text": "Calling tool.", "tool_calls": [{"name": "explode", "arguments": {}}]},
                {"text": "That failed.", "tool_calls": []},
            ]
        )
        agent = Agent(model=model, tools=[explode])
        run = agent.run_sync("Do the thing")
        assert run.status == RunStatus.completed
        assert any(s.kind == StepKind.error for s in run.steps)
