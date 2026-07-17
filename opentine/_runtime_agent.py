"""Agent construction and top-level lifecycle."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

from opentine._runtime_model import Model
from opentine.autosave import Autosaver
from opentine.budget import Budget
from opentine.graph import Run, StepKind, step_id
from opentine.tools import tool_schema


class AgentBase:
    supports_resume = True

    def __init__(
        self,
        model: Model,
        tools: list[Callable] | None = None,
        system: str = "You are a helpful assistant.",
        max_steps: int = 30,
        max_output_chars: int = 8000,
        budget: Budget | None = None,
        autosave_path: str | None = None,
        autosave_every_n_steps: int = 0,
        autosave_every_seconds: float = 0.0,
    ):
        self.model = model
        functions = list(tools or [])
        self.tools = {function.__name__: function for function in functions}
        self.schemas = [tool_schema(function) for function in functions]
        self._tool_arguments = {
            schema["name"]: frozenset(schema["input_schema"]["properties"])
            for schema in self.schemas
        }
        self.system = system
        self.max_steps = max_steps
        self.max_output_chars = max_output_chars
        self.budget = budget
        self.autosave_path = autosave_path
        self.autosave_every_n_steps = autosave_every_n_steps
        self.autosave_every_seconds = autosave_every_seconds

    def _make_autosaver(self) -> Autosaver:
        return Autosaver(
            self.autosave_path,
            every_n_steps=self.autosave_every_n_steps,
            every_seconds=self.autosave_every_seconds,
        )

    async def _call_tool(self, name: str, arguments: dict) -> str:
        if not isinstance(arguments, dict):
            raise TypeError("tool arguments must be an object")
        unexpected = set(arguments) - self._tool_arguments.get(name, frozenset())
        if unexpected:
            rendered = ", ".join(sorted(unexpected))
            raise ValueError(f"tool {name!r} received forbidden argument(s): {rendered}")
        result = self.tools[name](**arguments)
        result = await result if asyncio.iscoroutine(result) else result
        output = str(result)
        if len(output) > self.max_output_chars:
            output = output[: self.max_output_chars - 14] + "... (truncated)"
        return f"[Tool output from {name}] {output}"

    async def run(self, prompt: str, run_id: str | None = None) -> Run:
        identifier = run_id or step_id(
            StepKind.model, {"created_at": time.time_ns(), "prompt": prompt}
        )
        run = Run(
            id=identifier,
            model_info=self.model.name,
            system_prompt=self.system,
            user_prompt=prompt,
            manifest={
                "kind": "opentine-native",
                "model": {"name": self.model.name},
                "replay": ["cache", "rerun"],
                "resume": True,
                "tools": [schema["name"] for schema in self.schemas],
            },
            policies={},
            metadata={
                "model_info": self.model.name,
                "system_prompt": self.system,
                "user_prompt": prompt,
            },
        )
        if self.budget is not None:
            run.manifest["budget"] = self.budget.to_dict()
        messages = [{"role": "user", "content": prompt}]
        run.transcript.append({"role": "user", "content": prompt})
        autosaver = self._make_autosaver()
        try:
            await self._continue(run, messages, autosaver=autosaver)
        finally:
            if autosaver.path is not None:
                await asyncio.to_thread(autosaver.flush, run)
        return run

    def run_sync(self, prompt: str, run_id: str | None = None) -> Run:
        return asyncio.run(self.run(prompt, run_id))

    def replay_sync(self, run: Run, mode="cache") -> Run:
        return asyncio.run(self.replay(run, mode))

    def resume_sync(self, run: Run, from_step: str | None = None, prompt: str | None = None) -> Run:
        return asyncio.run(self.resume(run, from_step, prompt))
