"""Round-8 audit regressions, group F: OpenAI usage cache details across both spellings.

openai_missing_usage treats a cache field found in EITHER details object
(input_tokens_details or prompt_tokens_details) as present; openai_usage used to
extract only from the first truthy object, silently dropping the cache partition
when a gateway emitted both spellings. The two must agree.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

from opentine.models._chat_billing import chat_meter
from opentine.models._usage import openai_missing_usage, openai_usage


def _both_details(**overrides: object) -> SimpleNamespace:
    payload = {
        "prompt_tokens": 1_000_000,
        "completion_tokens": 0,
        "total_tokens": 1_000_000,
    }
    payload.update(overrides)
    return SimpleNamespace(**payload)


def test_cache_details_on_prompt_tokens_details_only():
    usage = openai_usage(
        _both_details(
            prompt_tokens_details=SimpleNamespace(
                cached_tokens=100_000, cache_write_tokens=200_000
            ),
        )
    )
    assert usage.cache_read == 100_000
    assert usage.cache_write_5m == 200_000
    assert usage.input == 700_000


def test_cache_details_on_input_tokens_details_only():
    usage = openai_usage(
        _both_details(
            input_tokens_details=SimpleNamespace(cached_tokens=100_000, cache_write_tokens=200_000),
        )
    )
    assert usage.cache_read == 100_000
    assert usage.cache_write_5m == 200_000
    assert usage.input == 700_000


def test_field_seen_by_missing_usage_guard_is_also_extracted():
    """The finder's exact divergence: guard satisfied, extractor blind."""
    raw = SimpleNamespace(
        input_tokens=1_000_000,
        output_tokens=0,
        input_tokens_details=SimpleNamespace(cached_tokens=0),
        prompt_tokens_details=SimpleNamespace(cache_write_tokens=200_000),
    )
    assert openai_missing_usage(raw, require_cache_write=True) == ()
    usage = openai_usage(raw)
    assert usage.cache_write_5m == 200_000
    assert usage.to_dict() == {
        "input": 800_000,
        "cache_write_5m": 200_000,
        "total": 1_000_000,
    }


def test_both_details_objects_combine_per_field_without_double_counting():
    usage = openai_usage(
        _both_details(
            input_tokens_details=SimpleNamespace(cached_tokens=800_000),
            prompt_tokens_details=SimpleNamespace(
                cached_tokens=800_000, cache_write_tokens=100_000
            ),
        )
    )
    assert usage.cache_read == 800_000
    assert usage.cache_write_5m == 100_000
    assert usage.input == 100_000


def test_present_but_empty_details_object_does_not_mask_the_other():
    for empty in (SimpleNamespace(), {}):
        usage = openai_usage(
            _both_details(
                input_tokens_details=empty,
                prompt_tokens_details=SimpleNamespace(cached_tokens=800_000),
            )
        )
        assert usage.cache_read == 800_000
        assert usage.input == 200_000


def test_authoritative_zero_still_blocks_top_level_fallbacks():
    usage = openai_usage(
        _both_details(
            input_tokens_details=SimpleNamespace(),
            prompt_tokens_details=SimpleNamespace(cached_tokens=0),
            prompt_cache_hit_tokens=800_000,
        )
    )
    assert usage.cache_read == 0
    assert usage.input == 1_000_000


def test_reasoning_read_from_completion_details_when_output_details_present():
    usage = openai_usage(
        _both_details(
            completion_tokens=50,
            total_tokens=1_000_050,
            output_tokens_details=SimpleNamespace(),
            completion_tokens_details=SimpleNamespace(reasoning_tokens=30),
        )
    )
    assert usage.reasoning == 30
    assert usage.output == 20


def test_gpt56_bills_cache_partition_when_both_detail_objects_present():
    written = chat_meter(
        "openai",
        "gpt-5.6",
        _both_details(
            input_tokens_details=SimpleNamespace(cached_tokens=0),
            prompt_tokens_details=SimpleNamespace(cache_write_tokens=200_000),
        ),
        None,
        None,
        None,
        False,
        "gpt-5.6",
    )
    assert written["billing"]["status"] == "complete"
    assert Decimal(written["billing"]["amount_usd"]) == Decimal("10.50")
    assert written["usage"]["cache_write_5m"] == 200_000
    read = chat_meter(
        "openai",
        "gpt-5.6",
        _both_details(
            input_tokens_details=SimpleNamespace(cache_write_tokens=0),
            prompt_tokens_details=SimpleNamespace(cached_tokens=800_000),
        ),
        None,
        None,
        None,
        False,
        "gpt-5.6",
    )
    assert read["billing"]["status"] == "complete"
    assert Decimal(read["billing"]["amount_usd"]) == Decimal("2.80")
    assert read["usage"]["cache_read"] == 800_000
