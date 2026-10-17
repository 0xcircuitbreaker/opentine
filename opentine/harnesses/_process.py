"""Subprocess-backed harness implementation."""

from __future__ import annotations

import asyncio
import math
import os
import time
from collections.abc import Mapping, Sequence
from io import StringIO
from pathlib import Path
from typing import Any

from opentine.core import StepKind
from opentine.harnesses._stream_io import Budget, pump, stderr_step
from opentine.harnesses._types import HarnessStep, StepCallback
from opentine.redaction import redact_text
from opentine.tools._batch_guard import refuse_batch_injection
from opentine.tools._process import _attach_kill_job, _cleanup_owned, _group_flags

DEFAULT_TIMEOUT_SECONDS = 3_600.0
DEFAULT_MAX_OUTPUT_CHARS = 4_000_000
DEFAULT_MAX_EVENTS = 10_000
DEFAULT_MAX_LINE_BYTES = 1_000_000
#: What a CLI needs to find its own login and config (``--harness-login-env``).
LOGIN_ENV_KEYS = ("PATH", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA")
LOGIN_ENV_KEYS += ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME")


class ProcessHarness:
    name = "process"
    default_command: tuple[str, ...] = ()
    login_env_keys: tuple[str, ...] = ()
    #: Kind of the step recording the launch; a harness that reports its real
    #: model calls makes it a non-model record so pricing does not see a phantom.
    invocation_kind: StepKind = StepKind.model

    def __init__(
        self,
        *,
        command: Sequence[str] | None = None,
        extra_args: Sequence[str] | None = None,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        login_env: bool = False,
        env_allowlist: Sequence[str] | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
        max_events: int = DEFAULT_MAX_EVENTS,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    ):
        timeout_seconds = float(timeout_seconds)
        max_output_chars = int(max_output_chars)
        max_events = int(max_events)
        max_line_bytes = int(max_line_bytes)
        if (
            not math.isfinite(timeout_seconds)
            or min(timeout_seconds, max_output_chars, max_events, max_line_bytes) <= 0
        ):
            raise ValueError("harness resource limits must be positive and finite")
        self.command = tuple(command or self.default_command)
        self.extra_args = tuple(extra_args or ())
        self.cwd = Path(cwd) if cwd else None
        self.env = dict(env or {})
        self.login_env = login_env
        self.env_allowlist = tuple(env_allowlist or ())
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars
        self.max_events = max_events
        self.max_line_bytes = max_line_bytes

    @property
    def model_info(self) -> str:
        return self.name

    @property
    def supports_resume(self) -> bool:
        return False

    def build_command(self, task: str, context: dict[str, Any] | None = None) -> list[str]:
        if not isinstance(task, str):
            raise TypeError("harness task must be a string")
        # An untrusted prompt such as ``--dangerously-enable-x`` must not parse as an option;
        # flag-value and positional harnesses share no portable end-of-options convention.
        if task.startswith("-"):
            raise ValueError("harness task cannot begin with '-' (prefix it with prose)")
        return [*self.command, *self.extra_args, task]

    async def execute(
        self,
        task: str,
        context: dict[str, Any] | None = None,
        step_callback: StepCallback | None = None,
    ) -> dict[str, Any]:
        if not self.command:
            raise RuntimeError(f"No command configured for {self.name}")
        command = self.build_command(task, context)
        refuse_batch_injection(command)
        started = time.time()
        if step_callback:
            step_callback(
                HarnessStep(
                    kind=self.invocation_kind,
                    inputs={"command": command, "cwd": str(self.cwd or Path.cwd())},
                    model_info=self.model_info,
                )
            )
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(self.cwd) if self.cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.build_env(),
            limit=self.max_line_bytes,
            **_group_flags(),
        )
        transport = getattr(process, "_transport", None)
        native = transport.get_extra_info("subprocess") if os.name == "nt" and transport else None
        if os.name == "nt" and native is None:
            # Started suspended: without its Popen it can be neither contained nor
            # resumed, and would hang until the timeout. Never leave it half-started.
            process.kill()
            raise RuntimeError(f"{self.name} subprocess handle is unavailable")
        job = _attach_kill_job(native) if native is not None else None
        output_buffer, error_buffer = StringIO(), StringIO()
        output, errors = process.stdout, process.stderr
        if output is None or errors is None:
            _cleanup_owned(process, job)
            raise RuntimeError(f"{self.name} subprocess output pipe is unavailable")
        budget = Budget(self.name, self.max_output_chars, self.max_events)
        common = {"budget": budget, "emit": step_callback, "max_line_bytes": self.max_line_bytes}

        async def read_output() -> None:
            await asyncio.gather(
                pump(
                    output,
                    stream_name="stdout",
                    buffer=output_buffer,
                    parse=self.parse_line,
                    **common,
                ),
                pump(
                    errors,
                    stream_name="stderr",
                    buffer=error_buffer,
                    parse=self.parse_stderr_line,
                    **common,
                ),
            )

        cleaned = False

        async def cleanup() -> None:
            nonlocal cleaned
            if cleaned:
                return
            cleaned = True
            if os.name == "nt":
                await asyncio.to_thread(_cleanup_owned, process, job)
            else:
                _cleanup_owned(process, job)

        async def wait_parent() -> int:
            while process.returncode is None:
                await asyncio.sleep(0.01)
            return process.returncode

        def close_output() -> None:
            for fd in (1, 2):
                pipe = transport.get_pipe_transport(fd) if transport is not None else None
                if pipe is not None:
                    pipe.close()

        async def finish_reader() -> None:
            done, _ = await asyncio.wait((reader,), timeout=0.2)
            if reader not in done:
                close_output()
            await reader

        reader = asyncio.create_task(read_output())
        waiter = asyncio.create_task(wait_parent())
        try:
            async with asyncio.timeout(self.timeout_seconds):
                done, _ = await asyncio.wait((reader, waiter), return_when=asyncio.FIRST_COMPLETED)
                if waiter in done:
                    returncode = waiter.result()
                    await cleanup()
                    await finish_reader()
                else:
                    await reader
                    returncode = await waiter
        except TimeoutError as exc:
            raise TimeoutError(
                f"{self.name} exceeded its {self.timeout_seconds:g}-second timeout"
            ) from exc
        finally:
            await cleanup()
            if not reader.done():
                close_output()
            for task in (reader, waiter):
                if not task.done():
                    task.cancel()
            await asyncio.gather(reader, waiter, return_exceptions=True)
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except (TimeoutError, ProcessLookupError):
                pass
        output, stderr = output_buffer.getvalue(), error_buffer.getvalue()
        if returncode != 0:
            if step_callback:
                # Redact the whole text, then cut: a tail sliced first can start
                # inside a key whose BEGIN marker fell outside it.
                step_callback(
                    HarnessStep(
                        kind=StepKind.error,
                        inputs={
                            "output": redact_text(output)[-4000:],
                            **({"stderr": redact_text(stderr)[-4000:]} if stderr else {}),
                            "returncode": returncode,
                        },
                        duration=time.time() - started,
                    )
                )
            raise RuntimeError(f"{self.name} exited with status {returncode}")
        result: dict[str, Any] = {"output": output, "returncode": returncode}
        if stderr:
            result["stderr"] = stderr
        return result

    def build_env(self) -> dict[str, str]:
        built: dict[str, str] = {}
        if self.login_env:
            keys = {*LOGIN_ENV_KEYS, *self.login_env_keys, *self.env_allowlist}
            built.update({key: value for key in keys if (value := os.environ.get(key))})
        built.update(self.env)
        return built

    def parse_line(self, line: str) -> HarnessStep | list[HarnessStep] | None:
        return HarnessStep.from_line(line, model_info=self.model_info) if line else None

    def parse_stderr_line(self, line: str) -> HarnessStep | None:
        """A stderr line is recorded as text, never parsed as a structured event."""
        return stderr_step(line, self.model_info)
