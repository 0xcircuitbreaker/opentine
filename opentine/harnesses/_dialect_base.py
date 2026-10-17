"""Shared machinery for agent-CLI *dialects*: one event stream -> priceable steps.

Every terminal coding agent with a headless JSON mode reports the same few
things in its own words -- which model answered, what each call cost in tokens,
which tools ran and what they returned, and sometimes the CLI's own dollar
figure. A dialect (one small class per event schema, several CLIs per schema)
translates those words into :class:`HarnessStep` records in OpenTine's exclusive
usage buckets, so ``tine price`` can re-price any harness run from the signed
catalog, not only Claude Code's.

Token conventions differ, and getting them wrong misprices silently (the 0.8.2
OTel 4.4x bug). Each dialect states whether its ``input`` already *includes*
cached tokens (OpenAI/Gemini style) and whether ``output`` includes reasoning;
:func:`usage` subtracts so every bucket is exclusive, never negative.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

from opentine.core import StepKind
from opentine.harnesses._types import MAX_COUNT, HarnessStep, bounded_number

MAX_RESULT_CHARS = 64_000

#: CLI provider ids -> OpenTine catalog provider names. Unknown ids pass through:
#: an honest "unknown" price beats a guessed card.
PROVIDER_ALIASES = {
    "gemini": "google",
    "google-genai": "google",
    "google-vertex": "vertex",
    "vertex-ai": "vertex",
    "amazon-bedrock": "bedrock",
    "aws-bedrock": "bedrock",
    "azure": "foundry",
    "azure-openai": "foundry",
    "x-ai": "xai",
    "grok": "xai",
    "moonshot": "kimi",
    "moonshotai": "kimi",
    "zai": "glm",
    "z-ai": "glm",
    "zhipuai": "glm",
    "zai-coding-plan": "glm",
    "dashscope": "qwen",
    "alibaba": "qwen",
    "mistralai": "mistral",
    "togetherai": "together",
}


def count(value: Any) -> int:
    """A token count as a non-negative int; anything else is 0."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value if 0 <= value <= MAX_COUNT else 0
    if isinstance(value, float) and math.isfinite(value) and 0 <= value <= MAX_COUNT:
        return int(value)
    return 0


def money(value: Any) -> float:
    """A reported USD amount, or 0.0: a malformed figure must not abort the run."""
    if not isinstance(value, int | float):
        return 0.0
    return bounded_number(value) or 0.0


def provider_name(raw: Any) -> str:
    name = str(raw or "").strip().lower()
    return PROVIDER_ALIASES.get(name, name)


def split_model(raw: Any, provider: str = "") -> tuple[str, str]:
    """``"anthropic/claude-x"`` -> ``("claude-x", "anthropic")``; else as given."""
    model = str(raw or "").strip()
    if "/" in model and not provider:
        head, _, tail = model.partition("/")
        if head and tail:
            return tail, provider_name(head)
    return model, provider


def usage(
    *,
    input: Any = 0,
    output: Any = 0,
    cache_read: Any = 0,
    cache_write: Any = 0,
    cache_write_1h: Any = 0,
    reasoning: Any = 0,
    input_includes_cache: bool = False,
    output_includes_reasoning: bool = False,
) -> dict[str, int]:
    """Usage in OpenTine's exclusive buckets, zero buckets dropped."""
    read, write, write_1h = count(cache_read), count(cache_write), count(cache_write_1h)
    write_1h = min(write_1h, write) if write else write_1h
    source_input, source_output, think = count(input), count(output), count(reasoning)
    if input_includes_cache:
        source_input = max(source_input - read - write, 0)
    if output_includes_reasoning:
        think = min(think, source_output)
        source_output -= think
    buckets = {
        "input": source_input,
        "output": source_output,
        "cache_read": read,
        "cache_write_5m": max(write - write_1h, 0) if write else 0,
        "cache_write_1h": write_1h,
        "reasoning": think,
    }
    return {name: value for name, value in buckets.items() if value}


def text_of(content: Any) -> str:
    """Text out of a string, a list of content blocks, or a ``{"text": ...}``."""
    if isinstance(content, str):
        return content
    if isinstance(content, Mapping):
        return str(content.get("text") or content.get("content") or "")
    if isinstance(content, Sequence) and not isinstance(content, bytes | bytearray):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, Mapping) and block.get("type") in (None, "text", "output_text"):
                parts.append(str(block.get("text") or ""))
        return "\n".join(part for part in parts if part)
    return ""


def clipped(value: Any) -> dict[str, Any]:
    text = value if isinstance(value, str) else text_of(value) if value is not None else ""
    return {"result": text[:MAX_RESULT_CHARS], "truncated": len(text) > MAX_RESULT_CHARS}


def flag_value(command: Sequence[str], *flags: str) -> str:
    """The LAST value given to any of *flags* (``--model x`` or ``--model=x``)."""
    found = ""
    for index, token in enumerate(command):
        name, eq, inline = token.partition("=")
        if eq and name in flags:
            found = inline
        elif token in flags and index + 1 < len(command):
            found = command[index + 1]
    return found


def model_step(
    model: str,
    provider: str,
    tokens: dict[str, int],
    *,
    text: str = "",
    calls: list[dict[str, Any]] | None = None,
    cost: float = 0.0,
    **inputs: Any,
) -> HarnessStep:
    return HarnessStep(
        kind=StepKind.model,
        inputs={key: value for key, value in inputs.items() if value is not None},
        outputs={"text": text, "tool_calls": calls or []},
        model_info=model or None,
        provider=provider,
        usage=tokens,
        cost=cost,
    )


def tool_step(
    name: Any, arguments: Any, result: Any, model: str = "", *, error: bool = False, **extra: Any
) -> HarnessStep:
    return HarnessStep(
        kind=StepKind.tool,
        inputs={"name": str(name or "tool"), "arguments": arguments, **extra},
        outputs={**clipped(result), "is_error": bool(error)},
        model_info=model or None,
    )


def think_step(text: Any, model: str = "", **extra: Any) -> HarnessStep:
    extra = {key: value for key, value in extra.items() if value is not None}
    return HarnessStep(
        kind=StepKind.think, inputs={"text": text, **extra}, model_info=model or None
    )


def error_step(error: Any, model: str = "", **extra: Any) -> HarnessStep:
    return HarnessStep(
        kind=StepKind.error, inputs={"error": error, **extra}, model_info=model or None
    )


def done_step(
    result: Any, cli: str, model: str = "", *, cost: float = 0.0, failed: bool = False, **extra: Any
) -> HarnessStep:
    """The CLI's closing record; its own dollar figure is booked here, if any."""
    return HarnessStep(
        kind=StepKind.error if failed else StepKind.done,
        inputs={"event": "result", "reported_by": cli, **extra},
        outputs=clipped(result),
        model_info=model or None,
        cost=money(cost),
    )


__all__ = [
    "MAX_RESULT_CHARS",
    "PROVIDER_ALIASES",
    "clipped",
    "count",
    "done_step",
    "error_step",
    "flag_value",
    "model_step",
    "money",
    "provider_name",
    "split_model",
    "text_of",
    "think_step",
    "tool_step",
    "usage",
]
