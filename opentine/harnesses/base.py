"""Harness adapters that add opentine run trees to external agents."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from opentine.autosave import Autosaver
from opentine.budget import BudgetExceeded
from opentine.core import Run, RunStatus, StepKind, step_id


def _jsonable(value: Any) -> Any:
    """Convert arbitrary harness payloads into JSON-serializable data."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_jsonable(v) for v in value]
    if isinstance(value, bytes | bytearray):
        return value.decode(errors="replace")
    return repr(value)


def _coerce_kind(kind: StepKind | str) -> StepKind:
    if isinstance(kind, StepKind):
        return kind
    try:
        return StepKind(kind)
    except ValueError:
        return StepKind.think


def _short_id(prefix: str, payload: Mapping[str, Any]) -> str:
    return step_id(StepKind.model, {"prefix": prefix, **_jsonable(payload)})


@dataclass(slots=True)
class HarnessStep:
    """A normalized event emitted by an external agent harness."""

    kind: StepKind | str
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    parent_id: str | None = None
    model_info: str | None = None
    cost: float = 0.0
    duration: float = 0.0

    @classmethod
    def from_line(
        cls,
        line: str,
        *,
        kind: StepKind = StepKind.think,
        model_info: str | None = None,
    ) -> HarnessStep:
        return cls(kind=kind, inputs={"text": line}, model_info=model_info)


StepCallback = Callable[[HarnessStep], str]


class HarnessAdapter(Protocol):
    """Protocol implemented by wrappers for Claude Code, Codex, Cursor, etc."""

    @property
    def name(self) -> str: ...

    @property
    def model_info(self) -> str: ...

    @property
    def supports_resume(self) -> bool: ...

    def execute(
        self,
        task: str,
        context: dict[str, Any] | None = None,
        step_callback: StepCallback | None = None,
    ) -> Any | Awaitable[Any]: ...


class OpentineHarness:
    """Wrap any agent harness and record its execution as an opentine Run."""

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
            self.autosave_path, every_n_steps=autosave_steps, every_seconds=autosave_seconds
        )
        self._last_step_id: str | None = run.steps[-1].id if run and run.steps else None
        self._budget_breached = False

    async def execute(
        self,
        task: str,
        context: dict[str, Any] | None = None,
        *,
        save_path: str | Path | None = None,
    ) -> Run:
        """Execute the underlying harness and return the recorded run."""
        run = self._ensure_run(task, context)
        root = self.record_step(
            StepKind.model,
            inputs={
                "task": task,
                "context": context or {},
                "harness": self.harness.name,
            },
        )
        started = time.time()

        try:
            result = self.harness.execute(task, context=context, step_callback=self.record_step)
            if inspect.isawaitable(result):
                result = await result
            self.record_step(
                StepKind.done,
                inputs={"result": _jsonable(result)},
                outputs={"result": _jsonable(result)},
                parent_id=self._last_step_id or root,
                duration=time.time() - started,
            )
            run.status = RunStatus.completed
        except BudgetExceeded as exc:
            # A budget breach unwinds the stream loop via this exception (an
            # external CLI can't be paused mid-stream). Record one error step
            # (the breach flag stops record_step from re-raising), mark failed,
            # then honor on_breach: 'raise' propagates, 'stop' returns the run.
            self.record_step(
                StepKind.error,
                inputs={"error": f"BudgetExceeded: {exc.breach.dimension}"},
                outputs={"error": str(exc)},
                parent_id=self._last_step_id or root,
                duration=time.time() - started,
            )
            run.status = RunStatus.failed
            self._save_if_requested(save_path)
            budget = run.budget()
            if budget is not None and budget.on_breach == "raise":
                raise
            return run
        except Exception as exc:
            self.record_step(
                StepKind.error,
                inputs={"error": f"{type(exc).__name__}: {exc}"},
                outputs={"error": str(exc)},
                parent_id=self._last_step_id or root,
                duration=time.time() - started,
            )
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
        """Record a harness event and return the new step id."""
        if isinstance(kind, HarnessStep):
            step = kind
            normalized_kind = _coerce_kind(step.kind)
            inputs = step.inputs
            outputs = step.outputs
            parent_id = step.parent_id
            model_info = step.model_info
            cost = step.cost
            duration = step.duration
        else:
            normalized_kind = _coerce_kind(kind)

        run = self._require_run()
        original_model_info = run.model_info
        if model_info:
            run.model_info = model_info
        added = run.add_step(
            normalized_kind,
            _jsonable(inputs or {}),
            outputs=_jsonable(outputs or {}),
            parent_id=parent_id or self._last_step_id,
            cost=cost,
            duration=duration,
        )
        run.model_info = original_model_info
        self._last_step_id = added.id
        self._autosave()
        self._enforce_budget(run)
        return added.id

    def _enforce_budget(self, run: Run) -> None:
        """Unwind the run if a budget is breached.

        An external CLI harness can't be paused mid-stream, so a breach raises
        BudgetExceeded to unwind the streaming loop; ``execute`` then translates
        that into the run's ``on_breach`` semantics (return for 'stop', re-raise
        for 'raise'). The ``_budget_breached`` flag makes this idempotent so the
        error-step recorded by ``execute`` does not re-trigger the raise.
        """
        if self._budget_breached:
            return
        budget = run.budget()
        if budget is None:
            return
        breach = budget.check(
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
            "usage": run.total_tokens,
            "steps": len(run.steps),
            "duration": run.total_duration,
        }
        run.status = RunStatus.failed
        raise BudgetExceeded(breach, run=run)

    def fork(self, from_step: int | str, new_run_id: str | None = None) -> Run:
        """Fork the current run from a step index or step id."""
        run = self._require_run()
        step_id_to_fork = run.steps[from_step].id if isinstance(from_step, int) else from_step
        forked = run.fork(step_id_to_fork, new_run_id=new_run_id)
        forked.metadata["next_harness"] = self.harness.name
        return forked

    def pause(self, path: str | Path) -> Path:
        return self._require_run().pause(path)

    def _ensure_run(self, task: str, context: dict[str, Any] | None) -> Run:
        if self.run is None:
            run_id = self.run_id or _short_id(
                "harness-run",
                {"harness": self.harness.name, "task": task, "created_at": time.time_ns()},
            )
            self.run = Run(
                id=run_id,
                model_info=self.harness.model_info,
                user_prompt=task,
                created_at=time.time(),
                manifest={
                    "kind": "external-harness",
                    "harness": self.harness.name,
                    "resume": bool(getattr(self.harness, "supports_resume", False)),
                    "replay": ["cache"],
                },
                metadata={"harness": self.harness.name, "context": _jsonable(context or {})},
            )
            self._last_step_id = None
        else:
            self.run.status = RunStatus.running
            self.run.model_info = self.run.model_info or self.harness.model_info
            self.run.metadata = {
                **self.run.metadata,
                "harness": self.harness.name,
                "context": _jsonable(context or {}),
            }
        return self.run

    def _require_run(self) -> Run:
        if self.run is None:
            raise RuntimeError("No active run. Call execute() before recording steps.")
        return self.run

    def _autosave(self) -> None:
        if self.run is not None:
            self._autosaver.maybe_save(self.run)

    def _save_if_requested(self, save_path: str | Path | None) -> None:
        if self.run is None:
            return
        if save_path:
            self.run.save(Path(save_path))  # explicit final save
        # Finalize the autosave checkpoint (strips the draft marker on success).
        self._autosaver.flush(self.run)


class ProcessHarness:
    """Base class for CLI-driven agent harnesses."""

    name = "process"
    default_command: tuple[str, ...] = ()
    login_env_keys: tuple[str, ...] = ()

    def __init__(
        self,
        *,
        command: Sequence[str] | None = None,
        extra_args: Sequence[str] | None = None,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        login_env: bool = False,
        env_allowlist: Sequence[str] | None = None,
    ):
        self.command = tuple(command or self.default_command)
        self.extra_args = tuple(extra_args or ())
        self.cwd = Path(cwd) if cwd else None
        self.env = dict(env or {})
        self.login_env = login_env
        self.env_allowlist = tuple(env_allowlist or ())

    @property
    def model_info(self) -> str:
        return self.name

    @property
    def supports_resume(self) -> bool:
        return False

    def build_command(self, task: str, context: dict[str, Any] | None = None) -> list[str]:
        return [*self.command, *self.extra_args, task]

    async def execute(
        self,
        task: str,
        context: dict[str, Any] | None = None,
        step_callback: StepCallback | None = None,
    ) -> dict[str, Any]:
        if not self.command:
            raise RuntimeError(f"No command configured for {self.name}")

        cmd = self.build_command(task, context)
        started = time.time()
        if step_callback:
            step_callback(
                HarnessStep(
                    kind=StepKind.model,
                    inputs={"command": cmd, "cwd": str(self.cwd or Path.cwd())},
                    model_info=self.model_info,
                )
            )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(self.cwd) if self.cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=self.build_env(),
        )

        lines: list[str] = []
        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").rstrip()
            lines.append(line)
            parsed = self.parse_line(line)
            if parsed and step_callback:
                step_callback(parsed)

        returncode = await proc.wait()
        output = "\n".join(lines)
        if returncode != 0:
            if step_callback:
                step_callback(
                    HarnessStep(
                        kind=StepKind.error,
                        inputs={"returncode": returncode, "output": output[-4000:]},
                        duration=time.time() - started,
                    )
                )
            raise RuntimeError(f"{self.name} exited with status {returncode}")

        return {"returncode": returncode, "output": output}

    def build_env(self) -> dict[str, str]:
        """Return the subprocess environment.

        Harnesses are isolated by default. Login-env mode only passes enough
        local shell state for authenticated CLIs to find their executable and
        config directories; explicit ``env`` values always win.
        """
        built: dict[str, str] = {}
        if self.login_env:
            keys = {
                "PATH",
                "HOME",
                "USERPROFILE",
                "APPDATA",
                "LOCALAPPDATA",
                "XDG_CONFIG_HOME",
                "XDG_DATA_HOME",
                "XDG_CACHE_HOME",
                *self.login_env_keys,
                *self.env_allowlist,
            }
            built.update({key: value for key in keys if (value := os.environ.get(key))})
        built.update(self.env)
        return built

    def parse_line(self, line: str) -> HarnessStep | None:
        if not line:
            return None
        return HarnessStep.from_line(line, model_info=self.model_info)


def parse_json_event(line: str) -> dict[str, Any] | None:
    """Parse JSONL-style harness output if a line is structured."""
    stripped = line.strip()
    if not stripped.startswith("{"):
        return None
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def cost_from_text(text: str) -> float:
    """Best-effort extraction for lines such as 'cost=$0.0123'."""
    match = re.search(r"(?:cost|price)\s*[=:]\s*\$?([0-9]+(?:\.[0-9]+)?)", text, re.I)
    return float(match.group(1)) if match else 0.0
