"""Provider wire-usage normalization and billing response helpers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opentine.billing import PricingCatalog, Usage, bill, known_cost

_MISSING = object()


def value(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def integer(obj: Any, name: str, default: int = 0) -> int:
    raw = value(obj, name, default)
    return int(raw or 0)


def openai_usage(raw: Any) -> Usage:
    """Normalize Responses or Chat Completions usage into exclusive buckets."""
    input_total = integer(raw, "input_tokens", integer(raw, "prompt_tokens"))
    output_total = integer(raw, "output_tokens", integer(raw, "completion_tokens"))
    input_details = value(raw, "input_tokens_details") or value(raw, "prompt_tokens_details")
    output_details = value(raw, "output_tokens_details") or value(raw, "completion_tokens_details")
    # Nested details take precedence; fall back to top-level fields used by
    # OpenAI-compatible providers (e.g. DeepSeek's prompt_cache_hit_tokens) so cache
    # reads are billed at the cache rate, not as fresh input.
    cached_raw = value(input_details, "cached_tokens", _MISSING)
    if cached_raw is _MISSING:
        cached_raw = value(raw, "cached_tokens", _MISSING)
    if cached_raw is _MISSING:
        cached_raw = value(raw, "prompt_cache_hit_tokens", 0)
    cached = int(cached_raw or 0)
    write_5m = integer(input_details, "cache_write_tokens")
    write_1h = integer(input_details, "cache_write_1h_tokens")
    reasoning = integer(output_details, "reasoning_tokens")
    return Usage(
        input=max(0, input_total - cached - write_5m - write_1h),
        output=max(0, output_total - reasoning),
        cache_read=cached,
        cache_write_5m=write_5m,
        cache_write_1h=write_1h,
        reasoning=reasoning,
        total=integer(raw, "total_tokens") or input_total + output_total,
    )


def anthropic_usage(raw: Any) -> Usage:
    creation = value(raw, "cache_creation")
    write_5m = integer(creation, "ephemeral_5m_input_tokens")
    write_1h = integer(creation, "ephemeral_1h_input_tokens")
    if not write_5m and not write_1h:
        write_5m = integer(raw, "cache_creation_input_tokens")
    input_count = integer(raw, "input_tokens")
    output_count = integer(raw, "output_tokens")
    cache_read = integer(raw, "cache_read_input_tokens")
    return Usage(
        input=input_count,
        output=output_count,
        cache_read=cache_read,
        cache_write_5m=write_5m,
        cache_write_1h=write_1h,
        total=input_count + output_count + cache_read + write_5m + write_1h,
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
    cached = integer(raw, "cached_content_token_count", integer(raw, "cachedContentTokenCount"))
    output = integer(raw, "candidates_token_count", integer(raw, "candidatesTokenCount"))
    reasoning = integer(raw, "thoughts_token_count", integer(raw, "thoughtsTokenCount"))
    total = integer(raw, "total_token_count", integer(raw, "totalTokenCount"))
    total = total or prompt + output + reasoning
    prompt_modalities = _google_modalities(raw, "prompt_tokens_details", "promptTokensDetails")
    cache_modalities = _google_modalities(raw, "cache_tokens_details", "cacheTokensDetails")
    audio_input = max(0, prompt_modalities.get("audio", 0) - cache_modalities.get("audio", 0))
    audio_cache = min(cached, cache_modalities.get("audio", 0))
    extra = {
        name: count
        for name, count in {
            "input_audio": audio_input,
            "cache_read_audio": audio_cache,
        }.items()
        if count
    }
    return Usage(
        input=max(0, prompt - cached - audio_input),
        output=output,
        cache_read=max(0, cached - audio_cache),
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
    return Usage(
        input=int(raw.get("prompt_eval_count") or 0),
        output=int(raw.get("eval_count") or 0),
        total=(int(raw.get("prompt_eval_count") or 0) + int(raw.get("eval_count") or 0)),
        extra=extra,
    )


def metered_response(
    provider: str,
    model: str,
    usage: Usage,
    *,
    catalog: PricingCatalog | None = None,
    rate_override: dict[str, Any] | None = None,
    service_tier: str | None = None,
    unmetered: bool = False,
    effective_at: str | None = None,
) -> dict[str, Any]:
    result = bill(
        provider,
        model,
        usage,
        catalog=catalog,
        rate_override=rate_override,
        service_tier=service_tier,
        unmetered=unmetered,
        effective_at=effective_at,
    )
    return {
        "usage": usage.to_dict(),
        "billing": result.to_dict(),
        "cost": known_cost(result),
    }
