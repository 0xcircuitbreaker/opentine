"""Generic external agent CLI harness profiles."""

from __future__ import annotations

from typing import Any

from opentine.core import StepKind
from opentine.harnesses._stdout_trust import StdoutTrust
from opentine.harnesses._types import duration_seconds, reported_meter
from opentine.harnesses.base import HarnessStep, ProcessHarness


class JSONOrTextHarness(StdoutTrust, ProcessHarness):
    """Process harness with generic JSON/JSONL and text parsing."""

    structured_tool_types = ("tool", "exec", "command", "shell", "edit", "read", "write")
    session_keys = ("session_id", "sessionId", "session", "conversation_id", "run_id", "runId")

    def parse_line(self, line: str) -> HarnessStep | None:
        if not line:
            return None
        data = self.json_event(line)
        if data:
            return self._parse_json_event(data)
        return self._parse_text_line(line)

    def _parse_json_event(self, data: dict[str, Any]) -> HarnessStep:
        event_type = str(data.get("type") or data.get("event") or data.get("kind") or "")
        lower = event_type.lower()
        cost, warn = reported_meter(data, "cost", "price")
        session = self._session_metadata(data)

        if any(token in lower for token in self.structured_tool_types):
            name = data.get("name") or data.get("tool") or data.get("command") or data.get("action")
            return HarnessStep(
                kind=StepKind.tool,
                inputs={
                    "name": str(name or "tool"),
                    "arguments": data.get("arguments", data.get("args", {})),
                    **session,
                    **warn,
                },
                outputs={"result": data.get("result") or data.get("output") or data.get("content")},
                cost=cost,
                duration=duration_seconds(data),
                model_info=self.model_info,
            )
        if "error" in lower or data.get("error"):
            return HarnessStep(
                kind=StepKind.error,
                inputs={"error": data.get("error") or data, **session, **warn},
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
                **warn,
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

    def _session_metadata(self, data: dict[str, Any]) -> dict[str, Any]:
        return {key: data[key] for key in self.session_keys if key in data}

    @staticmethod
    def _tool_name_from_text(line: str) -> str:
        lower = line.lower()
        for name in ("shell", "exec", "edit", "write", "read", "search", "tool"):
            if name in lower:
                return name
        return "tool"


class GenericHarness(JSONOrTextHarness):
    """User-supplied generic agent command.

    The operator wrote this command, so its stdout is trusted as theirs: a JSON
    line is an event and a "cost: $N" line is booked. Wrap the model's own text
    in your events if the command prints it.
    """

    name = "generic"
    structured_stdout = True
    meter_free_text = True

    @property
    def model_info(self) -> str:
        return "generic"


#: 0.9 names for CLI harnesses now built from the catalog (``_harness_catalog``).
_CATALOG_NAMES = {
    "HermesHarness": "hermes",
    "KimiCodeHarness": "kimi-code",
    "OpenClawHarness": "openclaw",
    "OpenCodeHarness": "opencode",
    "PiHarness": "pi",
}


def __getattr__(name: str) -> Any:
    if name in _CATALOG_NAMES:
        from opentine.harnesses._harness_catalog import HARNESS_CLASSES

        return HARNESS_CLASSES[_CATALOG_NAMES[name]]
    raise AttributeError(name)
