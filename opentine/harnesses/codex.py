"""OpenAI Codex CLI harness adapter."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from opentine.core import StepKind
from opentine.harnesses._codex_events import CODEX_EVENTS, CodexStream, command_model
from opentine.harnesses._stdout_trust import StdoutTrust
from opentine.harnesses._types import duration_seconds, reported_meter
from opentine.harnesses.base import HarnessStep, ProcessHarness

MAX_CONFIG_BYTES = 1_000_000


def _codex_config(env: dict[str, str]) -> dict[str, Any]:
    """``$CODEX_HOME/config.toml`` (default ``~/.codex``), read-only, best effort."""
    home = env.get("CODEX_HOME") or os.environ.get("CODEX_HOME") or ""
    path = Path(home) / "config.toml" if home else Path.home() / ".codex" / "config.toml"
    try:
        if not path.is_file() or path.stat().st_size > MAX_CONFIG_BYTES:
            return {}
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return {}


class CodexCLIHarness(StdoutTrust, ProcessHarness):
    """Run Codex through its CLI and capture its ``--json`` event stream.

    The default command is ``codex exec --json --skip-git-repo-check <task>``: the
    JSONL stream carries every command, patch, MCP and web-search call and the
    turn's token usage, so the run is priceable afterwards. The model comes from
    ``-m``/``--model`` or Codex's ``config.toml``. A text-mode command
    (``command=("codex", "exec")``) still records, heuristically, without usage.
    """

    name = "codex"
    default_command = ("codex", "exec", "--json", "--skip-git-repo-check")
    # ``--json`` is Codex's only output-format switch; its ``-o`` is
    # ``--output-last-message FILE``, not a format (re-audit #19).
    json_options = ("--json",)
    json_values = ()

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._stream: CodexStream | None = None

    @property
    def invocation_kind(self) -> StepKind:  # type: ignore[override]
        # With --json the turns are the model steps; the launch is not one.
        return StepKind.think if self._stdout_is_structured() else StepKind.model

    @property
    def model_info(self) -> str:
        return (self._stream.model if self._stream else "") or "codex"

    def session(self) -> CodexStream:
        if self._stream is None:
            self._stream = CodexStream(*self.resolve_model())
        return self._stream

    def resolve_model(self) -> tuple[str, str]:
        """``(model, provider)`` this command runs: flags first, then config.toml."""
        model, provider, profile = command_model(self.command + self.extra_args)
        config = _codex_config(self.env)
        profiles = config.get("profiles")
        chosen = profile or config.get("profile")
        layer = profiles.get(chosen, {}) if isinstance(profiles, dict) and chosen else {}
        layer = layer if isinstance(layer, dict) else {}
        model = model or str(layer.get("model") or config.get("model") or "")
        provider = provider or str(
            layer.get("model_provider") or config.get("model_provider") or ""
        )
        if provider == "oss":
            provider = str(config.get("oss_provider") or "oss")
        return model, provider or "openai"

    async def execute(
        self,
        task: str,
        context: dict[str, Any] | None = None,
        step_callback: Any = None,
    ) -> dict[str, Any]:
        self._stream = None  # a harness object may run more than once
        self.session()
        return await super().execute(task, context=context, step_callback=step_callback)

    def parse_line(self, line: str) -> HarnessStep | None:
        data = self.json_event(line)
        if data and isinstance(data.get("type"), str) and data["type"] in CODEX_EVENTS:
            return self.session().step(data)
        if data:
            return self._parse_json_event(data)

        lower = line.lower()
        if any(token in lower for token in ("tool", "exec", "shell", "patch", "read", "write")):
            return HarnessStep(
                kind=StepKind.tool,
                inputs={"name": self._tool_name_from_text(line), "line": line},
                cost=self.text_cost(line),
                model_info=self.model_info,
            )
        if "error" in lower or "failed" in lower:
            return HarnessStep(
                kind=StepKind.error,
                inputs={"text": line},
                cost=self.text_cost(line),
                model_info=self.model_info,
            )
        return HarnessStep(
            kind=StepKind.think,
            inputs={"text": line},
            cost=self.text_cost(line),
            model_info=self.model_info,
        )

    def _parse_json_event(self, data: dict[str, Any]) -> HarnessStep:
        event_type = str(data.get("type") or data.get("event") or data.get("kind") or "")
        lower = event_type.lower()
        cost, warn = reported_meter(data, "cost", "price")

        if "tool" in lower or lower in {"exec", "command", "patch"}:
            name = data.get("name") or data.get("tool") or data.get("command") or "tool"
            return HarnessStep(
                kind=StepKind.tool,
                inputs={
                    "name": str(name),
                    "arguments": data.get("arguments", data.get("args", {})),
                    **warn,
                },
                outputs={"result": data.get("result") or data.get("output")},
                cost=cost,
                duration=duration_seconds(data),
                model_info=self.model_info,
            )
        if "error" in lower:
            return HarnessStep(
                kind=StepKind.error,
                inputs={"error": data.get("error") or data, **warn},
                cost=cost,
                model_info=self.model_info,
            )
        return HarnessStep(
            kind=StepKind.think,
            inputs={"text": data.get("text") or data.get("message") or data, **warn},
            cost=cost,
            model_info=self.model_info,
        )

    @staticmethod
    def _tool_name_from_text(line: str) -> str:
        lower = line.lower()
        if "patch" in lower:
            return "apply_patch"
        if "shell" in lower or "exec" in lower:
            return "shell"
        if "read" in lower:
            return "read"
        if "write" in lower:
            return "write"
        return "codex"
