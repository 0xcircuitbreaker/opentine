"""Cursor agent harness adapter."""

from __future__ import annotations

from typing import Any

from opentine.core import StepKind
from opentine.harnesses._types import meter_value
from opentine.harnesses.base import HarnessStep, ProcessHarness, cost_from_text, parse_json_event


class CursorHarness(ProcessHarness):
    """Run a Cursor-compatible agent CLI and capture its events.

    Cursor's public automation surfaces vary by environment, so the default
    command is intentionally easy to override:

    ``CursorHarness(command=("cursor-agent", "run"))``
    """

    name = "cursor"
    default_command = ("cursor-agent", "run")

    @property
    def model_info(self) -> str:
        return "cursor"

    def parse_line(self, line: str) -> HarnessStep | None:
        data = parse_json_event(line)
        if data:
            return self._parse_json_event(data)

        lower = line.lower()
        if any(token in lower for token in ("tool", "terminal", "edit", "read", "apply")):
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
        cost = meter_value(data, "cost", "price")

        if "tool" in lower or lower in {"terminal", "edit", "read_file"}:
            name = data.get("name") or data.get("tool") or data.get("action") or "tool"
            return HarnessStep(
                kind=StepKind.tool,
                inputs={"name": str(name), "arguments": data.get("arguments", {})},
                outputs={"result": data.get("result") or data.get("output")},
                cost=cost,
                duration=data.get("duration") or 0.0,
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
        if "terminal" in lower:
            return "terminal"
        if "edit" in lower or "apply" in lower:
            return "edit"
        if "read" in lower:
            return "read"
        return "cursor"
