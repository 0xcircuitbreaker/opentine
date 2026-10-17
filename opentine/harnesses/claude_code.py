"""Claude Code harness adapter."""

from __future__ import annotations

from typing import Any

from opentine.core import StepKind
from opentine.harnesses._claude_env import new_traceparent, trace_id
from opentine.harnesses._claude_stream import STREAM_EVENTS, ClaudeStream
from opentine.harnesses._stdout_trust import StdoutTrust
from opentine.harnesses._types import reported_meter
from opentine.harnesses.base import HarnessStep, ProcessHarness


class ClaudeCodeHarness(StdoutTrust, ProcessHarness):
    """Run Claude Code through its CLI and record observable events.

    The default command is ``claude -p --output-format stream-json --verbose
    <task>``: the structured stream carries the model, each call's token usage,
    every tool call with its result, and Claude Code's own cost, so the run is
    priceable afterwards. A plain-text command (``command=("claude", "-p")``)
    still records, heuristically, without model or usage.
    """

    name = "claude-code"
    default_command = ("claude", "-p", "--output-format", "stream-json", "--verbose")
    invocation_kind = StepKind.think
    # Inferred from the command (the inherited ``structured_stdout = None``): the
    # default asks for stream-json, where a JSON line is Claude Code's own event.
    # ``claude -p`` (text) prints the model's answer, so a JSON-shaped line there
    # is the model's prose and must not forge cost, usage or tool steps.

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.traceparent: str | None = None
        self._stream = ClaudeStream(env=self.build_env)

    @property
    def trace_id(self) -> str | None:
        """The W3C trace id this session ran under (its ``TRACEPARENT``)."""
        return trace_id(self.traceparent)

    def build_env(self) -> dict[str, str]:
        env = super().build_env()
        if self.traceparent and "TRACEPARENT" not in env:
            env["TRACEPARENT"] = self.traceparent
        return env

    async def execute(
        self,
        task: str,
        context: dict[str, Any] | None = None,
        step_callback: Any = None,
    ) -> dict[str, Any]:
        # ``claude -p`` joins an inbound trace context, so Claude Code's own OTel
        # spans (when its telemetry is on) share this run's trace id.
        self.traceparent = self.env.get("TRACEPARENT") or new_traceparent()
        return await super().execute(task, context=context, step_callback=step_callback)

    @property
    def model_info(self) -> str:
        return self._stream.model or "claude-code"

    def parse_line(self, line: str) -> HarnessStep | list[HarnessStep] | None:
        data = self.json_event(line)
        if data and isinstance(data.get("type"), str) and data["type"] in STREAM_EVENTS:
            return self._stream.step(data)
        if data:
            return self._parse_json_event(data)

        lower = line.lower()
        if any(token in lower for token in ("tool:", "tool_use", "running", "reading", "editing")):
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

        if "tool" in lower:
            name = data.get("name") or data.get("tool") or data.get("tool_name") or "tool"
            return HarnessStep(
                kind=StepKind.tool,
                inputs={"name": str(name), "arguments": data.get("arguments", {}), **warn},
                outputs={"result": data.get("result") or data.get("output")},
                cost=cost,
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
        for name in ("read", "edit", "write", "bash", "search", "grep", "run"):
            if name in lower:
                return name
        return "claude-code"
