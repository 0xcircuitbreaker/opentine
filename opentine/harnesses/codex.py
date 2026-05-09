"""OpenAI Codex CLI harness adapter."""

from __future__ import annotations

from typing import Any

from opentine.core import StepKind
from opentine.harnesses.base import HarnessStep, ProcessHarness, cost_from_text, parse_json_event


class CodexCLIHarness(ProcessHarness):
    """Run Codex through its CLI and capture JSONL or verbose output.

    The default command is ``codex exec <task>``. Pass a custom ``command`` if
    your installation exposes a different entry point.
    """

    name = "codex"
    default_command = ("codex", "exec")

    @property
    def model_info(self) -> str:
        return "codex"

    def parse_line(self, line: str) -> HarnessStep | None:
        data = parse_json_event(line)
        if data:
            return self._parse_json_event(data)

        lower = line.lower()
        if any(token in lower for token in ("tool", "exec", "shell", "patch", "read", "write")):
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

    def _parse_json_event(self, data: dict[str, Any]) -> HarnessStep:
        event_type = str(data.get("type") or data.get("event") or data.get("kind") or "")
        lower = event_type.lower()
        cost = float(data.get("cost") or data.get("price") or 0.0)

        if "tool" in lower or lower in {"exec", "command", "patch"}:
            name = data.get("name") or data.get("tool") or data.get("command") or "tool"
            return HarnessStep(
                kind=StepKind.tool,
                inputs={"name": str(name), "arguments": data.get("arguments", data.get("args", {}))},
                outputs={"result": data.get("result") or data.get("output")},
                cost=cost,
                duration=float(data.get("duration") or 0.0),
                model_info=self.model_info,
            )
        if "error" in lower:
            return HarnessStep(
                kind=StepKind.error,
                inputs={"error": data.get("error") or data},
                cost=cost,
                model_info=self.model_info,
            )
        return HarnessStep(
            kind=StepKind.think,
            inputs={"text": data.get("text") or data.get("message") or data},
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
