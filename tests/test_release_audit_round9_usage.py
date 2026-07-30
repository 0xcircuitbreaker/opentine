"""Round-9 audit regressions, group usage: null totals must not mask the alias.

Round 8 aligned the DETAILS objects on one presence rule (present AND non-null,
field by field) but the top-level totals still read through
integer(raw, "input_tokens", integer(raw, "prompt_tokens")), where integer()
returns 0 for present-and-null instead of falling through to the alias. So
{"input_tokens": null, "prompt_tokens": 1_000_000} billed 0 input tokens while
openai_missing_usage reported the dimension covered. The same eager-default
class lived in google_usage / _google_modalities. Extraction and the presence
check must agree on every {absent, null, zero, populated} placement.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from opentine.models._chat_billing import chat_meter
from opentine.models._usage import (
    google_usage,
    missing_usage_dimensions,
    openai_missing_usage,
    openai_usage,
)

_ABSENT = object()
_STATES = {"absent": _ABSENT, "null": None, "zero": 0, "populated": 777}


def _payload(base: dict[str, Any], **fields: Any) -> dict[str, Any]:
    payload = dict(base)
    for name, state in fields.items():
        if state is not _ABSENT:
            payload[name] = state
    return payload


@pytest.mark.parametrize("alias_state", _STATES)
@pytest.mark.parametrize("preferred_state", _STATES)
@pytest.mark.parametrize(
    ("preferred", "alias", "dimension", "bucket"),
    [
        ("input_tokens", "prompt_tokens", "input", "input"),
        ("output_tokens", "completion_tokens", "output", "output"),
    ],
)
def test_openai_totals_extraction_agrees_with_presence_check(
    preferred: str, alias: str, dimension: str, bucket: str, preferred_state: str, alias_state: str
) -> None:
    """4-way matrix per spelling pair: first present-and-non-null value wins."""
    states = (_STATES[preferred_state], _STATES[alias_state])
    raw = _payload({}, **{preferred: states[0], alias: states[1]})
    expected = next((s for s in states if s is not _ABSENT and s is not None), 0)
    covered = any(s is not _ABSENT and s is not None for s in states)
    usage = openai_usage(raw)
    assert getattr(usage, bucket) == expected
    missing = missing_usage_dimensions(
        raw,
        {
            "input": ("input_tokens", "prompt_tokens"),
            "output": ("output_tokens", "completion_tokens"),
        },
    )
    assert (dimension not in missing) == covered
    # The two functions may never disagree: a covered dimension extracts the
    # populated value; an uncovered one extracts 0 and is reported missing.
    if dimension in missing:
        assert getattr(usage, bucket) == 0


def test_null_input_tokens_does_not_mask_prompt_tokens_in_billing() -> None:
    raw = {
        "prompt_tokens": 1_000_000,
        "completion_tokens": 1000,
        "total_tokens": 1_001_000,
        "cache_write_tokens": 0,
    }
    clean = chat_meter("openai", "gpt-5.6", dict(raw), None, None, None, False, "gpt-5.6")
    nulled = chat_meter(
        "openai",
        "gpt-5.6",
        {**raw, "input_tokens": None},
        None,
        None,
        None,
        False,
        "gpt-5.6",
    )
    assert openai_missing_usage({**raw, "input_tokens": None}, require_cache_write=True) == ()
    assert nulled["billing"]["amount_usd"] == clean["billing"]["amount_usd"]
    assert nulled["billing"]["status"] == "complete"
    assert nulled["usage"] == clean["usage"]


def test_null_total_with_cache_details_no_longer_raises() -> None:
    usage = openai_usage(
        {
            "input_tokens": None,
            "prompt_tokens": 1_000_000,
            "completion_tokens": 1000,
            "prompt_tokens_details": {"cached_tokens": 500_000},
        }
    )
    assert (usage.input, usage.cache_read) == (500_000, 500_000)


def test_null_output_with_reasoning_details_no_longer_raises() -> None:
    usage = openai_usage(
        {
            "output_tokens": None,
            "completion_tokens": 500,
            "prompt_tokens": 100,
            "completion_tokens_details": {"reasoning_tokens": 400},
        }
    )
    assert (usage.output, usage.reasoning) == (100, 400)


def test_attribute_payloads_follow_the_same_null_skipping_rule() -> None:
    """Pydantic/SDK objects expose null extras as attributes, not dict keys."""
    raw = SimpleNamespace(
        input_tokens=None,
        prompt_tokens=1_000_000,
        output_tokens=None,
        completion_tokens=1000,
        total_tokens=1_001_000,
    )
    usage = openai_usage(raw)
    assert (usage.input, usage.output) == (1_000_000, 1000)
    assert openai_missing_usage(raw) == ()


def test_selected_spelling_still_validates_with_its_own_name() -> None:
    with pytest.raises(ValueError, match="prompt_tokens"):
        openai_usage({"input_tokens": None, "prompt_tokens": -5})


@pytest.mark.parametrize(
    ("preferred", "alias", "bucket"),
    [
        ("prompt_token_count", "promptTokenCount", "input"),
        ("candidates_token_count", "candidatesTokenCount", "output"),
        ("thoughts_token_count", "thoughtsTokenCount", "reasoning"),
        ("cached_content_token_count", "cachedContentTokenCount", "cache_read"),
    ],
)
def test_google_null_snake_case_does_not_mask_camel_case(
    preferred: str, alias: str, bucket: str
) -> None:
    base = {"prompt_token_count": 1_000_000, "candidates_token_count": 100}
    base.pop(preferred, None)
    usage = google_usage(_payload(base, **{preferred: None, alias: 777}))
    assert getattr(usage, bucket) == 777
    missing = missing_usage_dimensions(
        _payload({}, **{preferred: None, alias: 777}), {"dim": (preferred, alias)}
    )
    assert missing == ()


def test_google_null_total_and_tool_use_fall_through_to_alias() -> None:
    usage = google_usage(
        {
            "prompt_token_count": 100,
            "candidates_token_count": 10,
            "tool_use_prompt_token_count": None,
            "toolUsePromptTokenCount": 7,
            "total_token_count": None,
            "totalTokenCount": 117,
        }
    )
    assert usage.input == 107
    assert usage.total == 117


def test_google_null_details_object_does_not_mask_camel_case_modalities() -> None:
    usage = google_usage(
        {
            "prompt_token_count": 1000,
            "candidates_token_count": 100,
            "prompt_tokens_details": None,
            "promptTokensDetails": [{"modality": "AUDIO", "tokenCount": 600}],
        }
    )
    assert usage.extra["input_audio"] == 600
    assert usage.input == 400


def test_google_null_modality_count_does_not_mask_camel_case_count() -> None:
    usage = google_usage(
        {
            "prompt_token_count": 1000,
            "candidates_token_count": 100,
            "promptTokensDetails": [{"modality": "AUDIO", "token_count": None, "tokenCount": 600}],
        }
    )
    assert usage.extra["input_audio"] == 600
