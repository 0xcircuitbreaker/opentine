"""Subprocess-backed harness implementation."""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from opentine.core import StepKind
from opentine.harnesses._types import HarnessStep, StepCallback


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
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(self.cwd) if self.cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=self.build_env(),
        )
        lines: list[str] = []
        assert process.stdout is not None
        async for raw in process.stdout:
            line = raw.decode(errors="replace").rstrip()
            lines.append(line)
            parsed = self.parse_line(line)
            if parsed and step_callback:
                step_callback(parsed)
        returncode = await process.wait()
        output = "\n".join(lines)
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
