"""0.8.2: new Claude / GPT-6 / Gemini / Grok cards and the wire rules they need.

Every price asserted here was verified against the vendor's own pricing page on
2026-10-08; the wire rules come from the vendors' documentation, quoted in the
adapter source.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import pytest

from opentine.billing import PricingCatalog, Usage, bill, load_catalogs
from opentine.models._anthropic_rules import model_rules
from opentine.models._chat import ChatCompletions
from opentine.models._chat_billing import requires_cache_write
from opentine.models._responses import ResponsesTransport, omits_temperature
from opentine.models.anthropic import Anthropic
from opentine.models.openai import OpenAI

#: Under every long-context threshold below (Haiku 5.5 100k, xAI 200k, GPT-6 272k).
USAGE = Usage(input=50_000, output=1_000_000)


@pytest.fixture(scope="module")
def catalog() -> PricingCatalog:
    return load_catalogs()


def _price(catalog, provider, model, usage=USAGE, **kwargs):
    kwargs.setdefault("effective_at", "2026-10-08")
    return bill(provider, model, usage, catalog=catalog, **kwargs)


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("claude-opus-5-5", "20.2"),
        ("claude-sonnet-5-5", "10.1"),
        ("claude-haiku-5-5", "0.505"),
        ("claude-mythos-5-1", "50.5"),
        ("claude-mythos-5", "50.5"),
        ("claude-sonnet-4-6", "15.15"),
    ],
)
def test_new_claude_cards_price_input_plus_output(catalog, model, expected):
    result = _price(catalog, "anthropic", model)
    assert result.status == "complete"
    assert result.amount_usd == Decimal(expected)


def test_claude_cache_reads_use_the_published_model_specific_literals(catalog):
    reads = Usage(cache_read=1_000_000)
    assert _price(catalog, "anthropic", "claude-opus-5-5", reads).amount_usd == Decimal("0.20")
    assert _price(catalog, "anthropic", "claude-mythos-5-1", reads).amount_usd == Decimal("0.25")
    # Sonnet 5.5's cache read was cut from $0.20 to $0.10 on 2026-10-07.
    before = _price(catalog, "anthropic", "claude-sonnet-5-5", reads, effective_at="2026-10-06")
    after = _price(catalog, "anthropic", "claude-sonnet-5-5", reads, effective_at="2026-10-07")
    assert before.amount_usd == Decimal("0.20")
    assert after.amount_usd == Decimal("0.10")


def test_claude_fast_mode_is_carded_where_anthropic_publishes_it(catalog):
    for model, expected in (("claude-opus-5-5", "40.4"), ("claude-opus-4-8", "50.5")):
        fast = _price(catalog, "anthropic", model, service_tier="fast")
        assert fast.amount_usd == Decimal(expected)
    sonnet = _price(catalog, "anthropic", "claude-sonnet-5-5", service_tier="fast")
    assert sonnet.status == "unknown"


def test_haiku_5_5_reprices_the_whole_request_over_100k_prompt_tokens(catalog):
    # "A request's prompt length counts all of its input tokens, including cache
    # reads and cache writes" -- so 60k input + 40k cache reads is exactly 100k.
    at = _price(catalog, "anthropic", "claude-haiku-5-5", Usage(input=60_000, cache_read=40_000))
    over = _price(catalog, "anthropic", "claude-haiku-5-5", Usage(input=60_001, cache_read=40_000))
    assert at.calculation["context_rules"] == []
    assert at.amount_usd == Decimal("0.0064")
    assert over.calculation["context_rules"] == ["over-100k"]
    assert over.amount_usd == Decimal("0.0320005")


@pytest.mark.parametrize(
    ("model", "standard", "rates"),
    [
        ("gpt-6.1-sol", "10.1", ("2", "0.10", "2.50", "10")),
        ("gpt-6-sol", "10.1", ("2", "0.20", "2.50", "10")),
        ("gpt-6-luna", "0.505", ("0.10", "0.01", "0.125", "0.50")),
    ],
)
def test_new_gpt_6_cards(catalog, model, standard, rates):
    result = _price(catalog, "openai", model)
    assert result.amount_usd == Decimal(standard)
    per_million = result.calculation["rates_per_million"]
    assert (per_million["input"], per_million["output"]) == (rates[0], rates[3])
    card = catalog.lookup("openai", model, effective_at="2026-10-08")
    assert (card.rates["cache_read"], card.rates["cache_write_5m"]) == tuple(
        Decimal(rate) for rate in rates[1:3]
    )
    for tier, factor in (("batch", "0.5"), ("flex", "0.5"), ("fast", "2"), ("priority", "2")):
        priced = _price(catalog, "openai", model, service_tier=tier)
        assert priced.amount_usd == Decimal(standard) * Decimal(factor)
    long = _price(catalog, "openai", model, Usage(input=272_001))
    assert long.calculation["context_rules"] == ["over-272k"]


def test_ultrafast_is_carded_only_where_a_price_is_published(catalog):
    assert _price(catalog, "openai", "gpt-6.1-sol", service_tier="ultrafast").amount_usd == Decimal(
        "60.6"
    )
    for model in ("gpt-6-sol", "gpt-6-luna"):
        assert _price(catalog, "openai", model, service_tier="ultrafast").status == "unknown"


def test_gpt_5_6_cyber_carries_no_unpublished_tier_modifiers(catalog):
    assert _price(catalog, "openai", "gpt-5.6-cyber").status == "complete"
    for tier in ("batch", "flex", "fast", "priority"):
        assert _price(catalog, "openai", "gpt-5.6-cyber", service_tier=tier).status == "unknown"


def test_gemini_3_8_flash_introductory_card(catalog):
    assert _price(catalog, "google", "gemini-3.8-flash").amount_usd == Decimal("3.7875")
    batch = _price(catalog, "google", "gemini-3.8-flash", service_tier="batch")
    assert batch.amount_usd == Decimal("1.89375")
    assert (
        _price(catalog, "google", "gemini-3.8-flash", effective_at="2027-01-01").status == "unknown"
    )
    custom = _price(catalog, "google", "gemini-3.1-pro-preview-customtools")
    assert custom.rate_card_id == "google:gemini-3.1-pro:2026-02-19"


def test_grok_4_7_and_the_inclusive_200k_threshold(catalog):
    assert _price(catalog, "xai", "grok-4.7").amount_usd == Decimal("6.1")
    at = _price(catalog, "xai", "grok-4.7", Usage(input=200_000))
    below = _price(catalog, "xai", "grok-4.7", Usage(input=199_999))
    assert at.calculation["context_rules"] == ["at-least-200k"]
    assert below.calculation["context_rules"] == []
    for model in ("grok-4.6", "grok-4.7"):
        priority = _price(catalog, "xai", model, service_tier="priority")
        assert priority.amount_usd == Decimal("12.2")


def test_grok_latest_is_no_longer_aliased_to_grok_4_3(catalog):
    result = _price(catalog, "xai", "grok-latest")
    assert result.status == "unknown" and result.rate_card_id is None


@pytest.mark.parametrize(
    ("model", "restricted", "thinking"),
    [
        ("claude-opus-5", True, True),
        ("claude-opus-5-5", True, True),
        ("claude-sonnet-5-5", True, True),
        ("claude-haiku-5-5", True, True),
        ("claude-mythos-5-1", True, True),
        ("claude-fable-5-1", True, True),
        ("claude-haiku-4-5", False, False),
        ("claude-sonnet-4-5", False, True),
    ],
)
def test_anthropic_sampling_and_thinking_rules(model, restricted, thinking):
    supports, restricted_sampling, _ = model_rules(model)
    assert (restricted_sampling, supports) == (restricted, thinking)
    kwargs = Anthropic(model)._kwargs([], None, None, 0.0)
    # "non-default temperature, top_p, or top_k values return a 400 error on every request"
    assert ("temperature" in kwargs) is not restricted


@pytest.mark.parametrize(
    ("model", "omitted"),
    [
        ("gpt-6-astra", True),
        ("gpt-6.1-sol", True),
        ("gpt-6-sol", True),
        ("gpt-6-luna", True),
        ("gpt-5.6", True),
        ("o3", True),
        ("gpt-4o", False),
    ],
)
def test_openai_reasoning_models_never_receive_temperature(model, omitted):
    assert omits_temperature(model) is omitted
    responses = ResponsesTransport(model=model).kwargs([], None, None, 0.0)
    assert ("temperature" in responses) is not omitted
    chat = OpenAI(model, api_key="k", base_url="https://eu.example.test/v1")
    assert ("temperature" in chat._kwargs([], None, None, 0.0)) is not omitted


def test_gpt_6_is_recognized_as_a_reasoning_model():
    assert ChatCompletions("gpt-6.1-sol", provider="openai").supports_thinking


@pytest.mark.parametrize(
    ("provider", "model", "required"),
    [
        ("openai", "gpt-6-astra", True),
        ("openai", "gpt-6.1-sol", True),
        ("openai", "gpt-6-luna", True),
        ("openai", "gpt-5.6-sol", True),
        ("openai", "gpt-5.6", True),
        ("openai", "gpt-5", False),
        ("openai", "gpt-4o", False),
        ("openai", "not-a-carded-model", False),
        ("qwen", "qwen3.8-max", False),
    ],
)
def test_cache_write_usage_is_required_exactly_when_the_card_prices_it(
    catalog, provider, model, required
):
    assert requires_cache_write(provider, model, None, catalog) is required


def test_gpt_6_usage_without_cache_writes_is_not_billed_as_complete():
    # gpt-6-astra bills cache writes; a usage block that omits the count cannot be
    # silently priced as zero writes (this matched no "gpt-5.6" prefix before 0.8.2).
    usage = SimpleNamespace(
        input_tokens=1_000,
        output_tokens=10,
        input_tokens_details=SimpleNamespace(cached_tokens=0),
    )
    metered = ResponsesTransport(model="gpt-6-astra").meter(
        SimpleNamespace(usage=usage, model="gpt-6-astra")
    )
    assert metered["billing"]["status"] == "unknown"
    assert "cache_write_5m" in metered["billing"]["calculation"]["missing_usage_dimensions"]
