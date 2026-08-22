"""Provider-wire billing regressions from the final release audit."""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest

from opentine.billing import PricingCatalog, RateCard, Usage, bill, load_catalogs
from opentine.kernel import canonical_json
from opentine.models._chat import ChatCompletions
from opentine.models._responses import ResponsesTransport
from opentine.models._usage import anthropic_usage, openai_usage
from opentine.models.compat import Grok, Mistral, OpenRouter
from opentine.models.ollama import Ollama


def _usage(**values: Any) -> SimpleNamespace:
    defaults = {"prompt_tokens": 26, "completion_tokens": 168, "total_tokens": 498}
    defaults.update(values)
    return SimpleNamespace(**defaults)


def test_cache_fallbacks_treat_none_as_absent_but_zero_as_authoritative():
    fallback = openai_usage(
        _usage(
            prompt_tokens=100,
            completion_tokens=0,
            total_tokens=100,
            prompt_tokens_details=SimpleNamespace(cached_tokens=None),
            prompt_cache_hit_tokens=80,
        )
    )
    assert (fallback.input, fallback.cache_read) == (20, 80)
    mistral = openai_usage(
        _usage(prompt_tokens=100, completion_tokens=0, total_tokens=100, num_cached_tokens=70)
    )
    assert (mistral.input, mistral.cache_read) == (30, 70)
    nested_zero = openai_usage(
        _usage(
            prompt_tokens=100,
            completion_tokens=0,
            total_tokens=100,
            prompt_tokens_details=SimpleNamespace(cached_tokens=0),
            prompt_cache_hit_tokens=80,
        )
    )
    assert (nested_zero.input, nested_zero.cache_read) == (100, 0)


def test_xai_reasoning_is_additive_and_priority_requires_observed_tier():
    raw = _usage(completion_tokens_details=SimpleNamespace(reasoning_tokens=304))
    normalized = openai_usage(raw, additive_reasoning=True)
    assert normalized.to_dict() == {
        "input": 26,
        "output": 168,
        "reasoning": 304,
        "total": 498,
    }
    standard = Grok()._meter(raw, "default", "grok-4.5")
    assert standard["billing"]["status"] == "complete"
    assert Decimal(standard["billing"]["amount_usd"]) == Decimal("0.002884")
    uncertain = Grok(service_tier="priority")._meter(raw)
    assert uncertain["billing"]["status"] == "unknown"
    assert uncertain["billing"]["known_subtotal_usd"] == "0"
    priority = Grok(service_tier="priority")._meter(raw, "priority", "grok-4.5")
    assert Decimal(priority["billing"]["amount_usd"]) == Decimal("0.005768")
    downgraded = Grok(service_tier="priority")._meter(raw, "default", "grok-4.5")
    calculation = downgraded["billing"]["calculation"]
    assert calculation["requested_service_tier"] == "priority"
    assert calculation["service_tier"] == "default"
    exact = Grok(service_tier="priority")._meter(_usage(cost_in_usd_ticks=37_756_000))
    assert exact["billing"]["status"] == "complete"
    assert exact["billing"]["amount_usd"] == "0.0037756"
    assert exact["billing"]["rate_card_id"] is None
    invalid = Grok()._meter(_usage(cost_in_usd_ticks="37756000"))
    assert invalid["billing"]["status"] == "unknown"
    large = Grok()._meter(_usage(cost_in_usd_ticks=2**53))
    canonical_json(large)
    assert large["billing"]["calculation"]["provider_reported_cost_ticks"] == str(2**53)
    overridden = Grok(rates={"input": "2", "output": "6"})._meter(_usage(cost_in_usd_ticks=1))
    assert overridden["billing"]["calculation"].get("pricing_basis") is None


@pytest.mark.asyncio
async def test_xai_stream_emits_only_final_cumulative_usage():
    async def chunks():
        for completion, reasoning, finish in ((1, 2, None), (4, 6, "stop")):
            yield SimpleNamespace(
                choices=[SimpleNamespace(delta=SimpleNamespace(content="x"), finish_reason=finish)],
                model="grok-4.5",
                service_tier="default",
                usage=_usage(
                    prompt_tokens=3,
                    completion_tokens=completion,
                    total_tokens=3 + completion + reasoning,
                    completion_tokens_details=SimpleNamespace(reasoning_tokens=reasoning),
                    cost_in_usd_ticks=100 if finish is None else 200,
                ),
            )

    class Completions:
        async def create(self, **kwargs):
            return chunks()

    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    events = [event async for event in Grok()._stream(client, [])]
    usage_events = [event for event in events if event["type"] == "usage"]
    assert len(usage_events) == 1
    assert usage_events[0]["usage"] == {
        "input": 3,
        "output": 4,
        "reasoning": 6,
        "total": 13,
    }
    assert usage_events[0]["billing"]["amount_usd"] == "0.00000002"


def test_openai_gpt56_requires_reported_cache_write_dimension_and_tier():
    # Amounts track the current bundled gpt-5.6-sol card ($4 input / $5 cache write,
    # doubled here because 1M input tokens crosses the 272k long-context threshold).
    transport = ResponsesTransport(model="gpt-5.6", service_tier="priority")
    base = SimpleNamespace(input_tokens=1_000_000, output_tokens=0)
    missing = transport.meter(SimpleNamespace(model="gpt-5.6", usage=base))
    assert missing["billing"]["status"] == "unknown"
    assert missing["billing"]["known_subtotal_usd"] == "0"
    assert missing["cost"] == 0.0
    assert "cache_write_5m" in missing["billing"]["calculation"]["missing_usage_dimensions"]
    calculation = missing["billing"]["calculation"]
    assert calculation["components_usd"] == {}
    assert calculation["candidate_components_usd"] == {"input": "16"}
    assert calculation["candidate_known_subtotal_usd"] == "16"
    chat_missing = ChatCompletions("gpt-5.6", provider="openai")._meter(
        _usage(
            prompt_tokens=1_000_000,
            completion_tokens=0,
            total_tokens=1_000_000,
        ),
        None,
        "gpt-5.6",
    )
    assert chat_missing["billing"]["status"] == "unknown"
    assert chat_missing["billing"]["known_subtotal_usd"] == "0"
    assert chat_missing["cost"] == 0.0
    observed = transport.meter(
        SimpleNamespace(
            model="gpt-5.6",
            service_tier="default",
            usage=SimpleNamespace(
                input_tokens=1_000_000,
                output_tokens=0,
                input_tokens_details=SimpleNamespace(cache_write_tokens=0),
            ),
        )
    )
    assert observed["billing"]["status"] == "complete"
    assert Decimal(observed["billing"]["amount_usd"]) == Decimal("8")
    written = ResponsesTransport(model="gpt-5.6").meter(
        SimpleNamespace(
            model="gpt-5.6",
            usage=SimpleNamespace(
                input_tokens=1_000_000,
                output_tokens=0,
                input_tokens_details=SimpleNamespace(cache_write_tokens=200_000),
            ),
        )
    )
    assert Decimal(written["billing"]["amount_usd"]) == Decimal("8.4")


def test_catalog_aliases_preserve_explicit_override_scope():
    card = RateCard(
        "test:gpt56",
        "openai",
        "gpt-5.6-sol",
        {"input": Decimal("1"), "output": Decimal("1")},
        aliases=("gpt-5.6",),
    )
    catalog = PricingCatalog("test", (card,), "test")
    adapter = ChatCompletions(
        "gpt-5.6",
        provider="openai",
        rates={"input": "9", "output": "9"},
        catalog=catalog,
    )
    raw = _usage(
        prompt_tokens=1_000_000,
        completion_tokens=0,
        total_tokens=1_000_000,
        prompt_tokens_details=SimpleNamespace(cache_write_tokens=0),
    )
    aliased = adapter._meter(raw, None, "gpt-5.6-sol")
    assert Decimal(aliased["billing"]["amount_usd"]) == Decimal("9")
    mismatched = adapter._meter(raw, None, "different-model")
    assert mismatched["billing"]["status"] == "unknown"
    assert "ignored" in " ".join(mismatched["billing"]["warnings"])


def test_ollama_latest_and_mistral_aliases_keep_local_overrides():
    local = Ollama("llama3.1", input_cost_per_mtok=2, output_cost_per_mtok=4)._meter(
        {
            "model": "llama3.1:latest",
            "prompt_eval_count": 1_000_000,
            "eval_count": 1_000_000,
        }
    )
    assert local["billing"]["status"] == "complete"
    assert Decimal(local["billing"]["amount_usd"]) == Decimal("6")
    hosted = Mistral(
        "mistral-large-latest",
        rates={"input": "2", "cache_read": "1", "output": "4", "reasoning": "4"},
    )._meter(
        _usage(
            prompt_tokens=1_000_000,
            completion_tokens=1_000_000,
            total_tokens=2_000_000,
            num_cached_tokens=250_000,
        ),
        None,
        "mistral-large-2512",
    )
    assert Decimal(hosted["billing"]["amount_usd"]) == Decimal("5.75")


def test_openrouter_uses_reported_total_unless_rates_are_explicit():
    raw = _usage(
        prompt_tokens=1_000_000,
        completion_tokens=1_000_000,
        total_tokens=2_000_000,
        cost="0.123456789",
    )
    reported = OpenRouter()._meter(raw)
    assert reported["billing"]["status"] == "complete"
    assert reported["billing"]["amount_usd"] == "0.123456789"
    assert reported["billing"]["rate_card_id"] is None
    assert reported["billing"]["calculation"]["pricing_basis"] == "provider_reported_total"
    for invalid in (None, "-1", "Infinity", "not-money"):
        result = OpenRouter()._meter(_usage(cost=invalid))
        assert result["billing"]["status"] == "unknown" and result["cost"] == 0.0
    partial_byok = OpenRouter()._meter(_usage(cost="0.01", is_byok=True))
    assert partial_byok["billing"]["status"] == "partial"
    assert partial_byok["billing"]["known_subtotal_usd"] == "0.01"
    complete_byok = OpenRouter()._meter(
        _usage(
            cost="0.01",
            is_byok=True,
            cost_details={"upstream_inference_cost": "0.20"},
        )
    )
    assert complete_byok["billing"]["status"] == "complete"
    assert complete_byok["billing"]["amount_usd"] == "0.21"
    explicit = OpenRouter(rates={"input": "2", "output": "3"})._meter(raw)
    assert Decimal(explicit["billing"]["amount_usd"]) == Decimal("5")


def test_anthropic_thinking_is_an_exclusive_output_dimension():
    usage = anthropic_usage(
        {
            "input_tokens": 2,
            "output_tokens": 10,
            "output_tokens_details": {"thinking_tokens": 4},
        }
    )
    assert usage.input == 2 and usage.output == 6 and usage.reasoning == 4
    assert usage.total == 12


def test_gemini_pro_thresholds_apply_only_above_200k():
    catalog = load_catalogs()
    for model in ("gemini-3.1-pro-preview", "gemini-2.5-pro"):
        at = bill("google", model, Usage(input=200_000), catalog=catalog)
        over = bill("google", model, Usage(input=200_001), catalog=catalog)
        assert at.calculation["context_rules"] == []
        assert over.calculation["context_rules"] == ["over-200k"]
        assert (
            Decimal(over.calculation["rates_per_million"]["input"])
            == Decimal(at.calculation["rates_per_million"]["input"]) * 2
        )
    flash = bill("google", "gemini-3.5-flash", Usage(input=300_000), catalog=catalog)
    assert flash.calculation["context_rules"] == []


@pytest.mark.parametrize(
    ("model", "price"),
    [
        ("mistral-medium-3-5", "7.50"),
        ("mistral-large-2512", "1.50"),
        ("mistral-small-2603", "0.60"),
        ("ministral-14b-2512", "0.20"),
    ],
)
def test_mistral_reasoning_uses_the_documented_output_rate(model: str, price: str):
    result = bill("mistral", model, Usage(reasoning=1_000_000), catalog=load_catalogs())
    assert result.status == "complete"
    assert result.amount_usd == Decimal(price)


def test_deepseek_legacy_rates_end_before_v4_launch():
    catalog = load_catalogs()
    usage = Usage(input=1_000_000, output=1_000_000)
    legacy = bill("deepseek", "deepseek-chat", usage, catalog=catalog, effective_at="2026-04-23")
    gap = bill("deepseek", "deepseek-chat", usage, catalog=catalog, effective_at="2026-04-24")
    current = bill("deepseek", "deepseek-chat", usage, catalog=catalog, effective_at="2026-07-14")
    assert legacy.rate_card_id == "deepseek:deepseek-chat:legacy-2026-07"
    assert legacy.amount_usd == Decimal("0.70")
    assert gap.status == "unknown" and gap.rate_card_id is None
    assert current.rate_card_id == "deepseek:deepseek-v4-flash:2026-07-14"
