"""OpenAI Agents SDK harness adapter."""

from __future__ import annotations

import inspect
from typing import Any

from opentine.core import StepKind
from opentine.harnesses.base import HarnessStep, StepCallback, _jsonable


class OpenAIAgentsHarness:
    """Wrap an OpenAI Agents SDK agent/runner pair.

    This adapter avoids importing the SDK directly so opentine stays lightweight.
    Pass the already-created ``agent`` and, optionally, a runner object exposing
    ``run(agent, task)`` or ``run_sync(agent, task)``.
    """

    name = "openai-agents"

    def __init__(self, agent: Any, runner: Any | None = None, *, model_info: str | None = None):
        self.agent = agent
        self.runner = runner
        self._model_info = model_info

    @property
    def model_info(self) -> str:
        if self._model_info:
            return self._model_info
        model = getattr(self.agent, "model", None)
        name = getattr(model, "name", None) or getattr(model, "model", None)
        return f"openai-agents:{name}" if name else "openai-agents"

    async def execute(
        self,
        task: str,
        context: dict[str, Any] | None = None,
        step_callback: StepCallback | None = None,
    ) -> Any:
        if step_callback:
            step_callback(
                HarnessStep(
                    kind=StepKind.model,
                    inputs={"task": task, "context": context or {}},
                    model_info=self.model_info,
                )
            )

        result = self._invoke_runner(task)
        if inspect.isawaitable(result):
            result = await result

        if step_callback:
            step_callback(
                HarnessStep(
                    kind=StepKind.think,
                    inputs={"text": getattr(result, "final_output", result)},
                    outputs={"result": _jsonable(result)},
                    model_info=self.model_info,
                )
            )
        return result

    def _invoke_runner(self, task: str) -> Any:
        if self.runner is None:
            run = getattr(self.agent, "run", None)
            if not callable(run):
                raise RuntimeError("OpenAI agent does not expose run(); pass a runner object")
            return run(task)

        run = getattr(self.runner, "run", None)
        if callable(run):
            return run(self.agent, task)

        run_sync = getattr(self.runner, "run_sync", None)
        if callable(run_sync):
            return run_sync(self.agent, task)

        raise RuntimeError("Runner must expose run(agent, task) or run_sync(agent, task)")
