"""Gemini ``usageMetadata`` normalization, including per-modality buckets.

Prompt audio is split out because Gemini prices it apart from text. Output is
split by modality too -- ``output_image``, ``output_audio``, ``output_video`` --
because image, speech and video output are priced apart from text output
(nano-banana image models, native-audio and Omni video). A text-only response
reports only TEXT, so its usage is unchanged.
"""

from __future__ import annotations

from typing import Any

from opentine.billing import Usage
from opentine.models._usage import (
    _MAX_SAFE_INTEGER,
    _first_value,
    _safe_total,
    alias_integer,
    value,
)

#: Output modalities priced apart from text output.
_OUTPUT_MEDIA = ("image", "audio", "video")


def _google_modalities(raw: Any, name: str, wire_name: str) -> dict[str, int]:
    result: dict[str, int] = {}
    details = _first_value((raw, name), (raw, wire_name), default=[])
    for item in details or []:
        modality = str(value(item, "modality", "")).lower().rsplit(".", 1)[-1]
        if modality:
            count = alias_integer(item, "token_count", "tokenCount")
            result[modality] = result.get(modality, 0) + count
    return result


def google_usage(raw: Any) -> Usage:
    prompt = alias_integer(raw, "prompt_token_count", "promptTokenCount")
    tool_use = alias_integer(raw, "tool_use_prompt_token_count", "toolUsePromptTokenCount")
    cached = alias_integer(raw, "cached_content_token_count", "cachedContentTokenCount")
    output = alias_integer(raw, "candidates_token_count", "candidatesTokenCount")
    reasoning = alias_integer(raw, "thoughts_token_count", "thoughtsTokenCount")
    total = alias_integer(raw, "total_token_count", "totalTokenCount")
    total = total or _safe_total(prompt, output, reasoning, tool_use)
    prompt_modalities = _google_modalities(raw, "prompt_tokens_details", "promptTokensDetails")
    cache_modalities = _google_modalities(raw, "cache_tokens_details", "cacheTokensDetails")
    prompt_audio = prompt_modalities.get("audio", 0)
    audio_cache = cache_modalities.get("audio", 0)
    if cached > prompt or prompt_audio > prompt or audio_cache > min(cached, prompt_audio):
        raise ValueError("provider usage cache/audio sub-buckets exceed prompt token totals")
    audio_input = prompt_audio - audio_cache
    output_modalities = _google_modalities(
        raw, "candidates_tokens_details", "candidatesTokensDetails"
    )
    media_output = {f"output_{name}": output_modalities.get(name, 0) for name in _OUTPUT_MEDIA}
    if sum(media_output.values()) > output:
        raise ValueError("provider usage output modalities exceed candidate token totals")
    output -= sum(media_output.values())
    extra = {
        name: count
        for name, count in {
            "input_audio": audio_input,
            "cache_read_audio": audio_cache,
            **media_output,
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
