"""OpenAI-messages dialect: ``{"role": "assistant", ...}`` / ``{"role": "tool", ...}`` lines.

Kimi Code's ``--print --output-format stream-json`` (``docs/en/customization/print-mode.md``)
and Mistral Vibe's ``--output streaming`` emit chat messages as they complete.
Usage, when a line carries it, follows the Chat Completions convention: prompt
tokens *include* cached ones and completion tokens include reasoning.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opentine.harnesses._dialect_base import model_step, text_of, think_step, tool_step, usage
from opentine.harnesses._dialect_harness import Dialect
from opentine.harnesses._types import HarnessStep


class OpenAIMessages(Dialect):
    """``{"role": "assistant", ...}`` / ``{"role": "tool", ...}`` message lines."""

    cli = "openai-messages"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.tools: dict[str, tuple[str, Any]] = {}

    def step(self, data: dict[str, Any]) -> list[HarnessStep] | None:
        role = data.get("role")
        if role == "tool":
            call_id = str(data.get("tool_call_id") or "")
            name, arguments = self.tools.pop(call_id, (data.get("name") or "tool", None))
            return [
                tool_step(name, arguments, data.get("content"), self.model, tool_use_id=call_id)
            ]
        if role != "assistant":
            return [] if role in ("user", "system") else None
        self.set_model(data.get("model"))
        calls = []
        raw_calls = data.get("tool_calls")
        for call in raw_calls if isinstance(raw_calls, list) else []:
            function = call.get("function") if isinstance(call, Mapping) else None
            if isinstance(function, Mapping):
                call_id = str(call.get("id") or "")
                self.tools[call_id] = (
                    str(function.get("name") or "tool"),
                    function.get("arguments"),
                )
                calls.append(
                    {
                        "id": call_id,
                        "name": function.get("name"),
                        "arguments": function.get("arguments"),
                    }
                )
        raw = data.get("usage") if isinstance(data.get("usage"), Mapping) else {}
        details = (
            raw.get("prompt_tokens_details")
            if isinstance(raw.get("prompt_tokens_details"), Mapping)
            else {}
        )
        out_details = raw.get("completion_tokens_details")
        out_details = out_details if isinstance(out_details, Mapping) else {}
        tokens = usage(
            input=raw.get("prompt_tokens", raw.get("input_tokens")),
            output=raw.get("completion_tokens", raw.get("output_tokens")),
            cache_read=details.get("cached_tokens"),
            reasoning=out_details.get("reasoning_tokens"),
            input_includes_cache=True,
            output_includes_reasoning=True,
        )
        text = text_of(data.get("content"))
        if not tokens:
            return [think_step(text, self.model, tool_calls=calls or None)] if text or calls else []
        return [model_step(self.model, self.provider, tokens, text=text, calls=calls)]


class KimiCode(OpenAIMessages):
    cli = "kimi-code"
    default_provider = "kimi"


class MistralVibe(OpenAIMessages):
    cli = "vibe"
    default_provider = "mistral"


__all__ = ["KimiCode", "MistralVibe", "OpenAIMessages"]
