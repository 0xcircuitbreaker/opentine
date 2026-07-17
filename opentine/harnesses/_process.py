"""Subprocess-backed harness implementation."""

from __future__ import annotations

import asyncio
import math
import os
import subprocess
import time
from collections.abc import Mapping, Sequence
from io import StringIO
from pathlib import Path
from typing import Any

from opentine.core import StepKind
from opentine.harnesses._types import HarnessStep, StepCallback
from opentine.tools._process import _attach_kill_job, _cleanup_owned

DEFAULT_TIMEOUT_SECONDS = 3_600.0
DEFAULT_MAX_OUTPUT_CHARS = 4_000_000
DEFAULT_MAX_EVENTS = 10_000
DEFAULT_MAX_LINE_BYTES = 1_000_000


class ProcessHarness:
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
        # Prevent an untrusted prompt such as ``--dangerously-enable-x`` from
        # being parsed as another CLI option. Flag-value harnesses and positional
        # harnesses do not share a portable end-of-options convention.
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
        started = time.time()
        if step_callback:
            step_callback(
                HarnessStep(
                    kind=StepKind.model,
                    inputs={"command": command, "cwd": str(self.cwd or Path.cwd())},
                    model_info=self.model_info,
                )
            )
        group = (
            {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
            if os.name == "nt"
            else {"start_new_session": True}
        )
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(self.cwd) if self.cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=self.build_env(),
            limit=self.max_line_bytes,
            **group,
        )
        transport = getattr(process, "_transport", None)
        native = transport.get_extra_info("subprocess") if os.name == "nt" and transport else None
        job = _attach_kill_job(native) if native is not None else None
        output_buffer = StringIO()
        output_chars = events = 0
        saw_line = False
        assert process.stdout is not None

        async def read_output() -> None:
            nonlocal output_chars, events, saw_line
            while True:
                try:
                    raw = await process.stdout.readline()
                except ValueError as exc:
                    raise RuntimeError(
                        f"{self.name} output line exceeds {self.max_line_bytes} bytes"
                    ) from exc
                if not raw:
                    return
                line = raw.decode(errors="replace").rstrip("\r\n")
                separator_chars = 1 if saw_line else 0
                output_chars += separator_chars + len(line)
                if output_chars > self.max_output_chars:
                    raise RuntimeError(
                        f"{self.name} output exceeds {self.max_output_chars} characters"
                    )
                if saw_line:
                    output_buffer.write("\n")
                output_buffer.write(line)
                saw_line = True
                parsed = self.parse_line(line)
                if parsed:
                    events += 1
                    if events > self.max_events:
                        raise RuntimeError(
                            f"{self.name} emitted more than {self.max_events} events"
                        )
                    if step_callback:
                        step_callback(parsed)

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
            pipe = transport.get_pipe_transport(1) if transport is not None else None
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
        output = output_buffer.getvalue()
        if returncode != 0:
            if step_callback:
                step_callback(
                    HarnessStep(
                        kind=StepKind.error,
                        inputs={"output": output[-4000:], "returncode": returncode},
                        duration=time.time() - started,
                    )
                )
            raise RuntimeError(f"{self.name} exited with status {returncode}")
        return {"output": output, "returncode": returncode}

    def build_env(self) -> dict[str, str]:
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
        return HarnessStep.from_line(line, model_info=self.model_info) if line else None
