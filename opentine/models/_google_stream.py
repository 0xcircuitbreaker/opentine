"""Bounded Gemini stream aggregation and terminal validation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from opentine.models._continuation import MAX_PROVIDER_PARTS
from opentine.models._google_billing import google_header_tier
from opentine.models._provider_meta import model_name
from opentine.models._stream_content import google_content
from opentine.models._streaming import MAX_STREAM_CALLS, SizeBudget, TextBuffer, WarningList
from opentine.models._terminal import reject_refused_tool_calls, reject_unsafe_tool_calls
from opentine.models._usage import value


class GoogleStreamState:
    def __init__(self) -> None:
        self.text = TextBuffer("Google aggregate text")
        self.reasoning = TextBuffer("Google aggregate reasoning")
        self.refusal = TextBuffer("Google refusal", 4096)
        self.calls: list[dict[str, Any]] = []
        self.warnings: list[str] = WarningList()
        self.arguments = SizeBudget()
        self.continuation_budget = SizeBudget()
        self.continuation: list[dict[str, Any]] = []
        self.usage = None
        self.model = None
        self.service_tier = None
        self.saw_candidate = False
        self.terminal = False

    def add(self, chunk: Any) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        parsed = google_content(chunk, self.arguments)
        self.warnings.extend(parsed["warnings"])
        candidates = value(chunk, "candidates", []) or []
        if candidates:
            self.saw_candidate = True
            finish = value(candidates[0], "finish_reason")
            if finish and str(finish).split(".")[-1] == "STOP":
                self.terminal = True
        for record in parsed.get("google_content", []):
            if len(self.continuation) >= MAX_PROVIDER_PARTS:
                self.warnings.append(f"Google continuation truncated at {MAX_PROVIDER_PARTS} parts")
                break
            kept = self.continuation_budget.keep(record, self.warnings, "Google continuation")
            if isinstance(kept, dict) and not kept.get("_truncated"):
                self.continuation.append(kept)
        if parsed["text"]:
            self.text.add(parsed["text"])
            events.append({"type": "text_delta", "text": parsed["text"]})
        if parsed.get("reasoning_content"):
            thought = parsed["reasoning_content"]
            self.reasoning.add(thought)
            events.append({"type": "thinking_delta", "text": thought})
        available = max(0, MAX_STREAM_CALLS - len(self.calls))
        self.calls.extend(parsed["tool_calls"][:available])
        if parsed["tool_calls"][available:]:
            self.warnings.append(f"streamed tool calls truncated at {MAX_STREAM_CALLS} entries")
        self.refusal.add(parsed.get("refusal"))
        if value(chunk, "usage_metadata"):
            self.usage = value(chunk, "usage_metadata")
        reported_model = value(chunk, "model_version") or value(chunk, "modelVersion")
        if reported_model is not None:
            self.model = reported_model
        self.service_tier = google_header_tier(chunk) or self.service_tier
        return events

    def finish(
        self, meter: Callable[[Any, str | None, str | None], dict[str, Any]]
    ) -> list[dict[str, Any]]:
        metered = meter(self.usage, self.model, self.service_tier)
        events: list[dict[str, Any]] = [{"type": "usage", **metered}]
        if not self.saw_candidate and not self.refusal.text:
            self.refusal.add("provider returned no candidates")
        elif not self.terminal and not self.refusal.text:
            self.refusal.add("incomplete response: stream ended before STOP")
        for buffer in (self.text, self.reasoning, self.refusal):
            buffer.warn(self.warnings)
        result: dict[str, Any] = {
            "text": self.text.text,
            "tool_calls": self.calls,
            "warnings": self.warnings,
        }
        if self.reasoning.text:
            result["reasoning_content"] = self.reasoning.text
        if self.refusal.text:
            result["refusal"] = self.refusal.text
        if self.continuation:
            result["google_content"] = self.continuation
        if normalized_model := model_name(self.model):
            result["model"] = normalized_model
        reject_unsafe_tool_calls(result)
        reject_refused_tool_calls(result)
        if self.calls or self.refusal.text or self.reasoning.text or self.continuation:
            result.update(metered)
            events.append({"type": "response", **result})
        return events
