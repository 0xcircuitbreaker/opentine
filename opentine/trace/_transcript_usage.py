"""Token-usage conventions of agent-CLI transcripts, as exclusive buckets.

See :mod:`opentine.trace._transcript_common` for which CLI follows which.
"""

from __future__ import annotations

from typing import Any

_MAX_SAFE_INTEGER = (1 << 53) - 1


def count(value: Any) -> int | None:
    """A token count, from an int, an integral float, or a decimal string."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        text = value.strip()
        # ASCII digits only: str.isdigit() also accepts "²" and other Unicode
        # digits that int() then refuses, which aborted the whole import.
        if not (text.isascii() and text.isdigit() and len(text) <= 16):
            return None
        value = int(text)
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return value if type(value) is int and 0 <= value <= _MAX_SAFE_INTEGER else None


def _present(**dimensions: int | None) -> dict[str, int]:
    return {name: value for name, value in dimensions.items() if value}


def anthropic_usage(raw: Any) -> dict[str, int]:
    """Exclusive buckets from an Anthropic ``usage`` block (cache counts beside input)."""
    raw = raw if isinstance(raw, dict) else {}
    creation = raw.get("cache_creation") if isinstance(raw.get("cache_creation"), dict) else {}
    write_5m = count(creation.get("ephemeral_5m_input_tokens")) or 0
    write_1h = count(creation.get("ephemeral_1h_input_tokens")) or 0
    if not write_5m and not write_1h:
        write_5m = count(raw.get("cache_creation_input_tokens")) or 0
    output = count(raw.get("output_tokens")) or 0
    details = raw.get("output_tokens_details")
    reasoning = count(details.get("thinking_tokens")) if isinstance(details, dict) else None
    reasoning = reasoning if reasoning is not None and reasoning <= output else 0
    return _present(
        input=count(raw.get("input_tokens")),
        output=output - reasoning,
        cache_read=count(raw.get("cache_read_input_tokens")),
        cache_write_5m=write_5m,
        cache_write_1h=write_1h,
        reasoning=reasoning,
    )


def inclusive_usage(
    input_total: Any, cached: Any, output_total: Any, reasoning: Any, cache_write: Any = None
) -> dict[str, int]:
    """Exclusive buckets from OpenAI-style totals that include their sub-counts.

    A total smaller than its own sub-counts cannot include them; it is kept as
    reported rather than turned negative.
    """
    read, write = count(cached) or 0, count(cache_write) or 0
    thought = count(reasoning) or 0
    total_in, total_out = count(input_total), count(output_total)
    if total_in is not None and total_in >= read + write:
        total_in -= read + write
    if total_out is not None and total_out >= thought:
        total_out -= thought
    return _present(
        input=total_in,
        output=total_out,
        cache_read=read,
        cache_write_5m=write,
        reasoning=thought,
    )


def gemini_usage(
    prompt: Any, candidates: Any, cached: Any, thoughts: Any, tool: Any = None
) -> dict[str, int]:
    """Exclusive buckets from Gemini usage metadata (prompt includes the cache)."""
    read, tool_use = count(cached) or 0, count(tool) or 0
    fresh = count(prompt)
    if fresh is not None:
        fresh = (fresh - read if fresh >= read else fresh) + tool_use
    elif tool_use:
        fresh = tool_use
    return _present(
        input=fresh, output=count(candidates), cache_read=read, reasoning=count(thoughts)
    )


def claude_tier(speed: Any, geo: Any) -> str | None:
    """The card modifier a Claude call's ``speed`` / ``inference_geo`` select.

    The same rule as the Claude Code harness capture, so an imported session
    prices fast mode (``fast``/``fast_us``) and US-only inference (``us``) as
    the recorded run would, not at the standard rate.
    """
    fast, us = speed == "fast", geo == "us"
    if fast:
        return "fast_us" if us else "fast"
    return "us" if us else None


__all__ = ["anthropic_usage", "claude_tier", "count", "gemini_usage", "inclusive_usage"]
