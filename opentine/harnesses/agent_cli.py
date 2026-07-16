"""Generic external agent CLI harness profiles."""

from __future__ import annotations

from typing import Any

from opentine.core import StepKind
from opentine.harnesses._types import meter_value
from opentine.harnesses.base import HarnessStep, ProcessHarness, cost_from_text, parse_json_event


class JSONOrTextHarness(ProcessHarness):
    """Process harness with generic JSON/JSONL and text parsing."""

    structured_tool_types = ("tool", "exec", "command", "shell", "edit", "read", "write")
    session_keys = ("session_id", "sessionId", "session", "conversation_id", "run_id", "runId")

    def parse_line(self, line: str) -> HarnessStep | None:
        if not line:
            return None
        data = parse_json_event(line)
        if data:
            return self._parse_json_event(data)
        return self._parse_text_line(line)

    def _parse_json_event(self, data: dict[str, Any]) -> HarnessStep:
        event_type = str(data.get("type") or data.get("event") or data.get("kind") or "")
        lower = event_type.lower()
        cost = meter_value(data, "cost", "price")
        session = self._session_metadata(data)

        if any(token in lower for token in self.structured_tool_types):
            name = data.get("name") or data.get("tool") or data.get("command") or data.get("action")
            return HarnessStep(
                kind=StepKind.tool,
                inputs={
                    "name": str(name or "tool"),
                    "arguments": data.get("arguments", data.get("args", {})),
                    **session,
                },
                outputs={"result": data.get("result") or data.get("output") or data.get("content")},
                cost=cost,
                duration=meter_value(data, "duration", "duration_ms"),
                model_info=self.model_info,
            )
        if "error" in lower or data.get("error"):
            return HarnessStep(
                kind=StepKind.error,
                inputs={"error": data.get("error") or data, **session},
                cost=cost,
                model_info=self.model_info,
            )
        return HarnessStep(
            kind=StepKind.think,
            inputs={
                "text": data.get("text")
                or data.get("message")
                or data.get("content")
                or data.get("delta")
                or data,
                **session,
            },
            cost=cost,
            model_info=self.model_info,
        )

    def _parse_text_line(self, line: str) -> HarnessStep:
        lower = line.lower()
        if any(token in lower for token in ("tool", "exec", "shell", "edit", "read", "write")):
            return HarnessStep(
                kind=StepKind.tool,
                inputs={"name": self._tool_name_from_text(line), "line": line},
                cost=cost_from_text(line),
                model_info=self.model_info,
            )
        if "error" in lower or "failed" in lower:
            return HarnessStep(
                kind=StepKind.error,
                inputs={"text": line},
                cost=cost_from_text(line),
                model_info=self.model_info,
            )
        return HarnessStep(
            kind=StepKind.think,
            inputs={"text": line},
            cost=cost_from_text(line),
            model_info=self.model_info,
        )

    def _session_metadata(self, data: dict[str, Any]) -> dict[str, Any]:
        return {key: data[key] for key in self.session_keys if key in data}

    @staticmethod
    def _tool_name_from_text(line: str) -> str:
        lower = line.lower()
        for name in ("shell", "exec", "edit", "write", "read", "search", "tool"):
            if name in lower:
                return name
        return "tool"


class OpenCodeHarness(JSONOrTextHarness):
    """Run OpenCode through ``opencode run <task>``."""

    name = "opencode"
    default_command = ("opencode", "run")
    login_env_keys = ("OPENCODE_CONFIG",)

    @property
    def model_info(self) -> str:
        return "opencode"


class KimiCodeHarness(JSONOrTextHarness):
    """Run Kimi Code in print JSONL mode.

    Authenticate the CLI outside opentine with ``kimi login``.
    """

    name = "kimi-code"
    default_command = ("kimi", "--print", "--output-format", "stream-json", "--prompt")
    login_env_keys = ("KIMI_HOME",)

    @property
    def model_info(self) -> str:
        return "kimi-code"


class OpenClawHarness(JSONOrTextHarness):
    """Run OpenClaw in local JSON mode."""

    name = "openclaw"
    default_command = ("openclaw", "agent", "--local", "--json", "--message")
    login_env_keys = ("OPENCLAW_HOME",)

    @property
    def model_info(self) -> str:
        return "openclaw"


class HermesHarness(JSONOrTextHarness):
    """Run Hermes Agent through ``hermes chat -q <task>``."""

    name = "hermes"
    default_command = ("hermes", "chat", "-q")
    login_env_keys = ("HERMES_HOME",)

    @property
    def model_info(self) -> str:
        return "hermes"


class GenericHarness(JSONOrTextHarness):
    """User-supplied generic agent command."""

    name = "generic"

    @property
    def model_info(self) -> str:
        return "generic"


class PiHarness(GenericHarness):
    """User-supplied Pi orchestrator or Pi agent command."""

    name = "pi"

    @property
    def model_info(self) -> str:
        return "pi"
