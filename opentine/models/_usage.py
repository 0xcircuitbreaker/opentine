"""Provider wire-usage normalization and billing response helpers."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from opentine.billing import Usage

_MISSING = object()
_MAX_SAFE_INTEGER = (1 << 53) - 1


def _safe_total(*counts: int) -> int | None:
    total = sum(counts)
    return total if total <= _MAX_SAFE_INTEGER else None


def value(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def missing_usage_dimensions(raw: Any, fields: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    def present(name: str) -> bool:
        if isinstance(raw, Mapping):
            return name in raw and raw[name] is not None
        return raw is not None and hasattr(raw, name) and getattr(raw, name) is not None

    return tuple(dimension for dimension, names in fields.items() if not any(map(present, names)))


def integer(obj: Any, name: str, default: int = 0) -> int:
    raw = value(obj, name, default)
    if raw is None:
        return 0
    if type(raw) is int and 0 <= raw <= _MAX_SAFE_INTEGER:
        return raw
    if (
        type(raw) is float
        and math.isfinite(raw)
        and raw.is_integer()
        and 0 <= raw <= _MAX_SAFE_INTEGER
    ):
        return int(raw)
    raise ValueError(f"provider usage.{name} must be a non-negative safe integer")


def _first_value(*candidates: tuple[Any, str], default: Any = 0) -> Any:
    for source, name in candidates:
        raw = value(source, name, _MISSING)
        if raw is not _MISSING and raw is not None:
            return raw
    return default


def usage_field_present(raw: Any, *paths: tuple[str, ...]) -> bool:
    """Return whether any nested provider field is present and non-null."""
    for path in paths:
        current = raw
        for name in path:
            current = value(current, name, _MISSING)
            if current is _MISSING or current is None:
                break
        else:
            return True
    return False


def openai_missing_usage(raw: Any, *, require_cache_write: bool = False) -> tuple[str, ...]:
    missing = list(
        missing_usage_dimensions(
            raw,
            {
                "input": ("input_tokens", "prompt_tokens"),
                "output": ("output_tokens", "completion_tokens"),
            },
        )
    )
    cache_write_paths = (
        ("input_tokens_details", "cache_write_tokens"),
        ("prompt_tokens_details", "cache_write_tokens"),
        ("input_tokens_details", "cache_creation_input_tokens"),
        ("prompt_tokens_details", "cache_creation_input_tokens"),
        ("cache_write_tokens",),
    )
    if require_cache_write and not usage_field_present(raw, *cache_write_paths):
        missing.append("cache_write_5m")
    return tuple(missing)


def openai_usage(raw: Any, *, additive_reasoning: bool = False) -> Usage:
    """Normalize Responses or Chat Completions usage into exclusive buckets."""
    input_total = integer(raw, "input_tokens", integer(raw, "prompt_tokens"))
    output_total = integer(raw, "output_tokens", integer(raw, "completion_tokens"))
    input_details = (value(raw, "input_tokens_details"), value(raw, "prompt_tokens_details"))
    output_details = (value(raw, "output_tokens_details"), value(raw, "completion_tokens_details"))

    # Each field is read from whichever details spelling carries it — the same
    # either-object presence rule openai_missing_usage applies — then falls back
    # to top-level fields used by OpenAI-compatible providers (e.g. DeepSeek's
    # prompt_cache_hit_tokens) so cache reads bill at the cache rate, not as input.
    def detail(details: tuple[Any, Any], *names: str, fallbacks: tuple[str, ...] = ()) -> int:
        candidates = [(source, name) for name in names for source in details]
        raw_value = _first_value(*candidates, *((raw, name) for name in fallbacks))
        return integer({"value": raw_value}, "value")

    cached = detail(
        input_details,
        "cached_tokens",
        fallbacks=("cached_tokens", "prompt_cache_hit_tokens", "num_cached_tokens"),
    )
    write_5m = detail(
        input_details,
        "cache_write_tokens",
        "cache_creation_input_tokens",
        fallbacks=("cache_write_tokens",),
    )
    write_1h = detail(input_details, "cache_write_1h_tokens")
    reasoning = detail(output_details, "reasoning_tokens", fallbacks=("reasoning_tokens",))
    if cached + write_5m + write_1h > input_total:
        raise ValueError("provider usage input sub-buckets exceed total input tokens")
    if not additive_reasoning and reasoning > output_total:
        raise ValueError("provider usage reasoning tokens exceed total output tokens")
    normalized_output = output_total if additive_reasoning else output_total - reasoning
    computed_total = _safe_total(input_total, output_total, reasoning if additive_reasoning else 0)
    return Usage(
        input=input_total - cached - write_5m - write_1h,
        output=normalized_output,
        cache_read=cached,
        cache_write_5m=write_5m,
        cache_write_1h=write_1h,
        reasoning=reasoning,
        total=integer(raw, "total_tokens") or computed_total,
    )


def anthropic_usage(raw: Any) -> Usage:
    creation = value(raw, "cache_creation")
    write_5m = integer(creation, "ephemeral_5m_input_tokens")
    write_1h = integer(creation, "ephemeral_1h_input_tokens")
    if not write_5m and not write_1h:
        write_5m = integer(raw, "cache_creation_input_tokens")
    input_count = integer(raw, "input_tokens")
    output_count = integer(raw, "output_tokens")
    output_details = value(raw, "output_tokens_details")
    reasoning = integer(output_details, "thinking_tokens")
    if reasoning > output_count:
        raise ValueError("provider usage reasoning tokens exceed total output tokens")
    cache_read = integer(raw, "cache_read_input_tokens")
    return Usage(
        input=input_count,
        output=output_count - reasoning,
        cache_read=cache_read,
        cache_write_5m=write_5m,
        cache_write_1h=write_1h,
        reasoning=reasoning,
        total=_safe_total(input_count, output_count, cache_read, write_5m, write_1h),
    )


def _google_modalities(raw: Any, name: str, wire_name: str) -> dict[str, int]:
    result: dict[str, int] = {}
    details = value(raw, name, _MISSING)
    if details is _MISSING:
        details = value(raw, wire_name, [])
    for item in details or []:
        modality = str(value(item, "modality", "")).lower().rsplit(".", 1)[-1]
        if modality:
            count = integer(item, "token_count", integer(item, "tokenCount"))
            result[modality] = result.get(modality, 0) + count
    return result


def google_usage(raw: Any) -> Usage:
    prompt = integer(raw, "prompt_token_count", integer(raw, "promptTokenCount"))
    tool_use = integer(raw, "tool_use_prompt_token_count", integer(raw, "toolUsePromptTokenCount"))
    cached = integer(raw, "cached_content_token_count", integer(raw, "cachedContentTokenCount"))
    output = integer(raw, "candidates_token_count", integer(raw, "candidatesTokenCount"))
    reasoning = integer(raw, "thoughts_token_count", integer(raw, "thoughtsTokenCount"))
    total = integer(raw, "total_token_count", integer(raw, "totalTokenCount"))
    total = total or _safe_total(prompt, output, reasoning, tool_use)
    prompt_modalities = _google_modalities(raw, "prompt_tokens_details", "promptTokensDetails")
    cache_modalities = _google_modalities(raw, "cache_tokens_details", "cacheTokensDetails")
    prompt_audio = prompt_modalities.get("audio", 0)
    audio_cache = cache_modalities.get("audio", 0)
    if cached > prompt or prompt_audio > prompt or audio_cache > min(cached, prompt_audio):
        raise ValueError("provider usage cache/audio sub-buckets exceed prompt token totals")
    audio_input = prompt_audio - audio_cache
    extra = {
        name: count
        for name, count in {
            "input_audio": audio_input,
            "cache_read_audio": audio_cache,
        }.items()
        if count
    }
    fresh_input = prompt - cached - audio_input
    if fresh_input + tool_use > _MAX_SAFE_INTEGER:
        extra["input_tool_use"] = tool_use
    else:
        fresh_input += tool_use
    return Usage(
        input=fresh_input,
        output=output,
        cache_read=cached - audio_cache,
        reasoning=reasoning,
        total=total,
        extra=extra,
    )


def ollama_usage(raw: Mapping[str, Any]) -> Usage:
    extra = {
        key: raw[key]
        for key in (
            "total_seconds",
            "load_seconds",
            "prompt_eval_seconds",
            "eval_seconds",
        )
        if raw.get(key) is not None
    }
    input_count = integer(raw, "prompt_eval_count")
    output_count = integer(raw, "eval_count")
    return Usage(
        input=input_count,
        output=output_count,
        total=_safe_total(input_count, output_count),
        extra=extra,
    )
