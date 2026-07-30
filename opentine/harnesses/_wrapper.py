"""Run-recording wrapper for arbitrary external harnesses."""

from __future__ import annotations

import asyncio
import inspect
import time
from pathlib import Path
from typing import Any

from opentine.autosave import Autosaver
from opentine.budget import BudgetExceeded
from opentine.core import Run, RunStatus, StepKind
from opentine.harnesses._types import (
    HarnessAdapter,
    HarnessStep,
    _coerce_kind,
    _jsonable,
    _meter,
    _short_id,
)


class OpentineHarness:
    def __init__(
        self,
        harness: HarnessAdapter,
        *,
        run: Run | None = None,
        run_id: str | None = None,
        autosave_path: str | Path | None = None,
        autosave_steps: int = 0,
        autosave_seconds: float = 0.0,
    ):
        self.harness = harness
        self.run = run
        self.run_id = run_id
        self.autosave_path = Path(autosave_path) if autosave_path else None
        self.autosave_steps = autosave_steps
        self._autosaver = Autosaver(
            self.autosave_path,
            every_n_steps=autosave_steps,
            every_seconds=autosave_seconds,
        )
        self._last_step_id = run.steps[-1].id if run and run.steps else None
        self._budget_breached = False

    async def execute(
        self,
        task: str,
        context: dict[str, Any] | None = None,
        *,
        save_path: str | Path | None = None,
    ) -> Run:
        run = self._ensure_run(task, context)
        root = self.record_step(
            StepKind.model,
            inputs={"context": context or {}, "harness": self.harness.name, "task": task},
        )
        started = time.monotonic()
        try:
            result = self.harness.execute(task, context=context, step_callback=self.record_step)
            if inspect.isawaitable(result):
                budget = run.budget()
                timeout = (
                    max(
                        0,
                        budget.max_duration - run.total_duration - (time.monotonic() - started),
                    )
                    if budget is not None and budget.max_duration is not None
                    else None
                )
                if timeout is not None:
                    result = await asyncio.wait_for(result, timeout)
                else:
                    result = await result
            self.record_step(
                StepKind.done,
                inputs={"result": _jsonable(result)},
                outputs={"result": _jsonable(result)},
                parent_id=self._last_step_id or root,
                duration=time.monotonic() - started,
            )
            run.status = RunStatus.completed
        except BudgetExceeded as exc:
            self.record_step(
                StepKind.error,
                inputs={"error": f"BudgetExceeded: {exc.breach.dimension}"},
                outputs={"error": str(exc)},
                parent_id=self._last_step_id or root,
                duration=time.monotonic() - started,
            )
            run.status = RunStatus.failed
            self._save_if_requested(save_path)
            budget = run.budget()
            if budget is not None and budget.on_breach == "raise":
                raise
            return run
        except Exception as exc:
            try:
                self.record_step(
                    StepKind.error,
                    inputs={"error": f"{type(exc).__name__}: {exc}"},
                    outputs={"error": str(exc)},
                    parent_id=self._last_step_id or root,
                    duration=time.monotonic() - started,
                )
            except BudgetExceeded as budget_exc:
                run.status = RunStatus.failed
                self._save_if_requested(save_path)
                budget = run.budget()
                if budget is not None and budget.on_breach == "raise":
                    raise budget_exc
                return run
            run.status = RunStatus.failed
            self._save_if_requested(save_path)
            raise
        self._save_if_requested(save_path)
        return run

    def run_sync(
        self,
        task: str,
        context: dict[str, Any] | None = None,
        *,
        save_path: str | Path | None = None,
    ) -> Run:
        return asyncio.run(self.execute(task, context=context, save_path=save_path))

    def record_step(
        self,
        kind: HarnessStep | StepKind | str,
        inputs: dict[str, Any] | None = None,
        outputs: dict[str, Any] | None = None,
        *,
        parent_id: str | None = None,
        model_info: str | None = None,
        cost: float = 0.0,
        duration: float = 0.0,
    ) -> str:
        if isinstance(kind, HarnessStep):
            event = kind
            normalized = _coerce_kind(event.kind)
            inputs, outputs, parent_id = event.inputs, event.outputs, event.parent_id
            model_info, cost, duration = event.model_info, event.cost, event.duration
        else:
            normalized = _coerce_kind(kind)
        cost = _meter(cost, "cost")
        duration = _meter(duration, "duration")
        run = self._require_run()
        original_model = run.model_info
        if model_info:
            run.model_info = model_info
        added = run.add_step(
            normalized,
            _jsonable(inputs or {}),
            outputs=_jsonable(outputs or {}),
            parent_id=parent_id or self._last_step_id,
            cost=cost,
            duration=duration,
        )
        run.model_info = original_model
        self._last_step_id = added.id
        self._autosaver.maybe_save(run)
        self._enforce_budget(run)
        return added.id

    def _enforce_budget(self, run: Run) -> None:
        if self._budget_breached or run.budget() is None:
            return
        breach = run.budget().check(
            cost=run.total_cost,
            usage=run.total_tokens,
            steps=len(run.steps),
            duration=run.total_duration,
        )
        if breach is None:
            return
        self._budget_breached = True
        run.metadata["budget_state"] = {
            "breached": True,
            **breach.to_dict(),
            "cost": run.total_cost,
            "duration": run.total_duration,
            "steps": len(run.steps),
            "usage": run.total_tokens,
        }
        run.status = RunStatus.failed
        raise BudgetExceeded(breach, run=run)

    def fork(self, from_step: int | str, new_run_id: str | None = None) -> Run:
        run = self._require_run()
        step = run.steps[from_step].id if isinstance(from_step, int) else from_step
        forked = run.fork(step, new_run_id=new_run_id, intent={"harness": self.harness.name})
        forked.metadata["next_harness"] = self.harness.name
        return forked

    def pause(self, path: str | Path) -> Path:
        return self._require_run().pause(path)

    def _ensure_run(self, task: str, context: dict[str, Any] | None) -> Run:
        if self.run is None:
            identifier = self.run_id or _short_id(
                "harness-run",
                {"created_at": time.time_ns(), "harness": self.harness.name, "task": task},
            )
            self.run = Run(
                id=identifier,
                model_info=self.harness.model_info,
                user_prompt=task,
                created_at=time.time(),
                manifest={
                    "harness": self.harness.name,
                    "kind": "external-harness",
                    "replay": ["cache"],
                    "resume": bool(getattr(self.harness, "supports_resume", False)),
                },
                metadata={"context": _jsonable(context or {}), "harness": self.harness.name},
            )
            self._last_step_id = None
        else:
            self.run.status = RunStatus.running
            self.run.model_info = self.run.model_info or self.harness.model_info
            self.run.metadata.update(
                {"context": _jsonable(context or {}), "harness": self.harness.name}
            )
        return self.run

    def _require_run(self) -> Run:
        if self.run is None:
            raise RuntimeError("No active run. Call execute() before recording steps.")
        return self.run

    def _save_if_requested(self, save_path: str | Path | None) -> None:
        if self.run is None:
            return
        if save_path:
            self.run.save(Path(save_path))
        self._autosaver.flush(self.run)
