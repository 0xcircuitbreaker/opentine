"""Compare multiple agent harnesses under one opentine run format.

This demo uses tiny scripted harnesses so it runs anywhere. Swap the scripted
classes for ClaudeCodeHarness, CodexCLIHarness, or CursorHarness when those CLIs
are installed locally.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from opentine.core import StepKind
from opentine.harnesses import HarnessStep, OpentineHarness


@dataclass
class ScriptedHarness:
    name: str
    steps: list[str]
    cost_per_step: float

    @property
    def model_info(self) -> str:
        return self.name

    async def execute(self, task: str, context=None, step_callback=None) -> dict[str, Any]:
        for idx, text in enumerate(self.steps, start=1):
            await asyncio.sleep(0)
            if step_callback:
                step_callback(
                    HarnessStep(
                        kind=StepKind.think if idx == 1 else StepKind.tool,
                        inputs={"text": text} if idx == 1 else {"name": "edit", "arguments": text},
                        outputs={"ok": True},
                        cost=self.cost_per_step,
                    )
                )
        return {"task": task, "summary": f"{self.name} completed {len(self.steps)} steps"}


async def main() -> None:
    task = "Refactor auth middleware to use JWT"
    harnesses = [
        ScriptedHarness("claude-code", ["Plan refactor", "Edit auth.py", "Run tests"], 0.02),
        ScriptedHarness("codex", ["Inspect auth flow", "Patch middleware"], 0.015),
        ScriptedHarness("cursor", ["Open composer context", "Apply project-wide edit"], 0.01),
    ]

    runs = []
    for harness in harnesses:
        wrapped = OpentineHarness(harness)
        run = await wrapped.execute(task)
        run.save(f"{harness.name}_comparison.tine")
        runs.append(run)

    print("Harness comparison")
    for run in runs:
        print(f"- {run.id} {run.model_info}: steps={len(run.steps)} cost=${run.total_cost:.4f}")

    forked = runs[0].fork(runs[0].steps[1].id)
    forked.metadata["strategy"] = "retry-from-first-tool-with-cheaper-harness"
    forked.save("forked_from_claude_code.tine")
    print(f"Forked {runs[0].id} from step 1 -> {forked.id}")


if __name__ == "__main__":
    asyncio.run(main())
