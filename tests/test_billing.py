"""Golden tests for provider-neutral, effective-dated billing."""

from __future__ import annotations

from decimal import Decimal

import pytest

from opentine.billing import PricingCatalog, RateCard, Usage, bill, calculate, load_catalogs
from opentine.billing.catalog import BUNDLED_CATALOG
from opentine.models._metered import metered_response
from opentine.models._usage import google_usage, openai_usage
from opentine.models.google import Google
from opentine.runtime import Agent


@pytest.fixture(scope="module")
def catalog() -> PricingCatalog:
    return load_catalogs([BUNDLED_CATALOG])


def test_bundled_catalog_is_signed_and_exact_cache_arithmetic(catalog: PricingCatalog):
    assert catalog.signed
    assert catalog.id == f"sha256:{catalog.hash}"
    usage = Usage(
        input=1_000_000,
        output=1_000_000,
        cache_read=1_000_000,
        cache_write_5m=1_000_000,
        cache_write_1h=1_000_000,
    )
    result = bill("anthropic", "claude-fable-5", usage, catalog=catalog, effective_at="2026-07-14")
    assert result.status == "complete"
    assert result.amount_usd == Decimal("93.50")
    assert result.known_subtotal_usd == Decimal("93.50")
    assert result.catalog_provenance[0]["signature"]["algorithm"] == "ed25519"


@pytest.mark.parametrize("value", [True, 1.5, -1, "10"])
def test_usage_dict_rejects_noninteger_token_counts(value):
    with pytest.raises(ValueError, match="usage.input"):
        bill("openai", "gpt-5", {"input": value}, effective_at="2026-07-16")


def test_usage_extra_dimensions_cannot_override_core_tokens():
    with pytest.raises(ValueError, match="reserved"):
        Usage(input=1, extra={"input": 1_000_000})


def test_gpt_56_long_context_and_service_modifier(catalog: PricingCatalog):
    short = bill(
        "openai",
        "gpt-5.6",
        Usage(input=272_000, output=1_000_000),
        catalog=catalog,
        effective_at="2026-07-14",
    )
    long = bill(
        "openai",
        "gpt-5.6",
        Usage(input=273_000, output=1_000_000),
        catalog=catalog,
        effective_at="2026-07-14",
    )
    batch = bill(
        "openai",
        "gpt-5.6",
        Usage(input=273_000, output=1_000_000),
        catalog=catalog,
        effective_at="2026-07-14",
        service_tier="batch",
    )
    assert short.amount_usd == Decimal("31.360")
    assert long.amount_usd == Decimal("47.730")
    assert long.calculation["context_rules"] == ["over-272k"]
    assert batch.amount_usd == Decimal("23.8650")


def test_gpt_4o_effective_rates_and_snapshot_identity(catalog: PricingCatalog):
    usage = Usage(input=1_000_000, output=1_000_000)
    launch = bill("openai", "gpt-4o", usage, catalog=catalog, effective_at="2024-05-13")
    august = bill("openai", "gpt-4o", usage, catalog=catalog, effective_at="2024-08-06")
    cached = bill(
        "openai",
        "gpt-4o",
        Usage(input=1_000_000, cache_read=1_000_000, output=1_000_000),
        catalog=catalog,
        effective_at="2024-10-01",
    )
    old_snapshot = bill(
        "openai",
        "gpt-4o-2024-05-13",
        usage,
        catalog=catalog,
        effective_at="2026-07-16",
    )
    assert launch.amount_usd == Decimal("20")
    assert august.amount_usd == Decimal("12.50")
    assert cached.amount_usd == Decimal("13.75")
    assert old_snapshot.amount_usd == Decimal("20")


def test_anthropic_us_inference_geo_modifiers(catalog: PricingCatalog):
    usage = Usage(
        input=1_000_000,
        cache_read=1_000_000,
        cache_write_5m=1_000_000,
        cache_write_1h=1_000_000,
        output=1_000_000,
    )
    standard = bill(
        "anthropic", "claude-fable-5", usage, catalog=catalog, effective_at="2026-07-16"
    )
    us = bill(
        "anthropic",
        "claude-fable-5",
        usage,
        catalog=catalog,
        effective_at="2026-07-16",
        service_tier="us",
    )
    batch_us = bill(
        "anthropic",
        "claude-fable-5",
        usage,
        catalog=catalog,
        effective_at="2026-07-16",
        service_tier="batch_us",
    )
    unsupported = bill(
        "anthropic",
        "claude-sonnet-4-5",
        usage,
        catalog=catalog,
        effective_at="2026-07-16",
        service_tier="us",
    )
    assert standard.amount_usd == Decimal("93.50")
    assert us.amount_usd == Decimal("102.850")
    assert batch_us.amount_usd == Decimal("51.4250")
    assert unsupported.status == "unknown"


@pytest.mark.parametrize(
    ("canonical", "alias"),
    [
        ("mistral-medium-3-5", "mistral-medium-latest"),
        ("mistral-medium-3-5", "mistral-medium-3"),
        ("mistral-large-2512", "mistral-large-latest"),
        ("mistral-small-2603", "mistral-small-latest"),
        ("ministral-14b-2512", "ministral-14b-latest"),
    ],
)
def test_mistral_canonical_ids_and_stable_aliases(
    catalog: PricingCatalog, canonical: str, alias: str
):
    usage = Usage(input=1_000_000, output=1_000_000)
    exact = bill("mistral", canonical, usage, catalog=catalog, effective_at="2026-07-16")
    latest = bill("mistral", alias, usage, catalog=catalog, effective_at="2026-07-16")
    assert exact.status == "complete"
    assert latest.rate_card_id == exact.rate_card_id


@pytest.mark.parametrize(
    ("provider", "model"),
    [
        ("openai", "gpt-4o-latest"),
        ("openai", "gpt-5.6-terra-latest"),
        ("google", "gemini-3.1-pro"),
        ("groq", "qwen3-32b"),
        ("mistral", "mistral-large-3"),
        ("mistral", "ministral-3-14b"),
        ("anthropic", "claude-opus-4.8"),
        ("xai", "grok-4.20-latest"),
        ("glm", "glm-4-flash"),
        ("glm", "glm-5.2-latest"),
        ("kimi", "kimi-k2.6-thinking"),
        ("qwen", "qwen-max-latest"),
    ],
)
def test_unsupported_provider_aliases_remain_unpriced(
    catalog: PricingCatalog, provider: str, model: str
):
    result = bill(
        provider,
        model,
        Usage(input=1_000_000, output=1_000_000),
        catalog=catalog,
        effective_at="2026-07-16",
    )
    assert result.status == "unknown"
    assert result.rate_card_id is None


@pytest.mark.parametrize(
    ("model", "short_total", "long_total"),
    [
        ("grok-4.5", Decimal("6.83"), Decimal("13.660004")),
        ("grok-4.3", Decimal("2.895"), Decimal("5.79000250")),
        ("grok-4.20", Decimal("2.895"), Decimal("5.79000250")),
    ],
)
def test_grok_long_context_rates_start_above_200k(
    catalog: PricingCatalog,
    model: str,
    short_total: Decimal,
    long_total: Decimal,
):
    usage = Usage(input=100_000, cache_read=100_000, output=1_000_000, reasoning=100_000)
    short = bill("xai", model, usage, catalog=catalog, effective_at="2026-07-16")
    long = bill(
        "xai",
        model,
        Usage(input=100_001, cache_read=100_000, output=1_000_000, reasoning=100_000),
        catalog=catalog,
        effective_at="2026-07-16",
    )
    assert short.amount_usd == short_total
    assert short.calculation["context_rules"] == []
    assert long.amount_usd == long_total
    assert long.calculation["context_rules"] == ["over-200k"]
    assert all(
        Decimal(long.calculation["rates_per_million"][dimension])
        == Decimal(short.calculation["rates_per_million"][dimension]) * 2
        for dimension in ("input", "cache_read", "output", "reasoning")
    )


def test_qwen_plus_does_not_borrow_qwen36_rates(catalog: PricingCatalog):
    result = bill(
        "qwen",
        "qwen-plus",
        Usage(input=1_000_000, output=1_000_000),
        catalog=catalog,
        effective_at="2026-07-16",
    )
    assert result.status == "unknown"
    assert result.amount_usd is None
    assert result.rate_card_id is None


def test_qwen37_promotion_cache_modes_and_transition(catalog: PricingCatalog):
    usage = Usage(
        input=1_000_000,
        cache_read=1_000_000,
        cache_write_5m=1_000_000,
        output=1_000_000,
    )
    implicit = bill("qwen", "qwen3.7-max", usage, catalog=catalog, effective_at="2026-07-23")
    explicit = bill(
        "qwen",
        "qwen3.7-max",
        usage,
        catalog=catalog,
        effective_at="2026-07-23",
        service_tier="explicit_cache",
    )
    list_price = bill(
        "qwen",
        "qwen3.7-max",
        usage,
        catalog=catalog,
        effective_at="2026-07-24",
        service_tier="explicit_cache",
    )
    assert implicit.amount_usd == Decimal("6.8125")
    assert explicit.amount_usd == Decimal("6.6875")
    assert list_price.amount_usd == Decimal("13.375")


def test_qwen_explicit_cache_creation_usage_is_exclusive():
    usage = openai_usage(
        {
            "prompt_tokens": 100,
            "completion_tokens": 5,
            "prompt_tokens_details": {
                "cached_tokens": 10,
                "cache_creation_input_tokens": 20,
            },
        }
    )
    assert usage.input == 70
    assert usage.cache_read == 10
    assert usage.cache_write_5m == 20


def test_kimi_batch_uses_provider_exact_rates(catalog: PricingCatalog):
    result = bill(
        "kimi",
        "kimi-k2.6",
        Usage(input=1_000_000, cache_read=1_000_000, output=1_000_000, reasoning=1_000_000),
        catalog=catalog,
        effective_at="2026-07-16",
        service_tier="batch",
    )
    assert result.status == "complete"
    assert result.amount_usd == Decimal("5.47")
    assert result.calculation["service_rates_per_million"]["cache_read"] == "0.10"


def test_kimi_k3_current_default_rates(catalog: PricingCatalog):
    result = bill(
        "kimi",
        "kimi-k3",
        Usage(input=1_000_000, cache_read=1_000_000, output=1_000_000),
        catalog=catalog,
        effective_at="2026-07-16",
    )
    assert result.status == "complete"
    assert result.amount_usd == Decimal("18.30")
    assert result.rate_card_id == "kimi:kimi-k3:2026-07-16"


def test_groq_service_tiers_and_scoped_public_lifecycle(catalog: PricingCatalog):
    usage = Usage(input=1_000_000, output=1_000_000)
    flex = bill(
        "groq",
        "llama-3.3-70b-versatile",
        usage,
        catalog=catalog,
        effective_at="2026-07-16",
        service_tier="flex",
    )
    batch = bill(
        "groq",
        "llama-3.3-70b-versatile",
        usage,
        catalog=catalog,
        effective_at="2026-07-16",
        service_tier="batch",
    )
    qwen_batch = bill(
        "groq",
        "qwen/qwen3-32b",
        usage,
        catalog=catalog,
        effective_at="2026-07-16",
        service_tier="batch",
    )
    card = catalog.lookup("groq", "qwen/qwen3-32b", effective_at="2026-07-17")
    assert flex.amount_usd == Decimal("1.38")
    assert batch.amount_usd == Decimal("0.690")
    assert qwen_batch.status == "unknown"
    assert card is not None
    assert card.metadata["public_tier_shutdown"] == "2026-07-17"
    assert card.metadata["enterprise_committed_spend_exempt"] is True


def test_sonnet_5_introductory_rate_became_permanent(catalog: PricingCatalog):
    # Anthropic cancelled the 2026-09-01 rise to $3/$15 and made the $2/$10 launch
    # price standard, so the catalog carries one open-ended card. A scheduled-but-
    # cancelled future card would have overcharged every run from 2026-09-01 on.
    usage = Usage(input=1_000_000, output=1_000_000)
    intro = bill("anthropic", "claude-sonnet-5", usage, catalog=catalog, effective_at="2026-08-31")
    after = bill("anthropic", "claude-sonnet-5", usage, catalog=catalog, effective_at="2026-09-01")
    assert intro.rate_card_id == "anthropic:claude-sonnet-5:intro"
    assert intro.amount_usd == Decimal("12")
    assert after.rate_card_id == "anthropic:claude-sonnet-5:intro"
    assert after.amount_usd == Decimal("12")


def test_gpt_56_repricings_are_date_scoped(catalog: PricingCatalog):
    usage = Usage(input=1_000_000, output=1_000_000)

    def sol(when: str) -> tuple[str | None, Decimal | None]:
        result = bill("openai", "gpt-5.6-sol", usage, catalog=catalog, effective_at=when)
        return result.rate_card_id, result.amount_usd

    # Long-context multipliers apply: 2M input tokens crosses the 272k threshold.
    assert sol("2026-08-20") == ("openai:gpt-5.6-sol:2026-07-09", Decimal("55"))
    assert sol("2026-08-21") == ("openai:gpt-5.6-sol:2026-08-21", Decimal("38"))
    luna = bill("openai", "gpt-5.6-luna", usage, catalog=catalog, effective_at="2026-07-30")
    assert luna.rate_card_id == "openai:gpt-5.6-luna:2026-07-30"
    assert luna.amount_usd == Decimal("2.20")
    # Fast mode replaced priority processing on 2026-07-30 at the same 2x rate.
    fast = bill(
        "openai",
        "gpt-5.6-terra",
        Usage(input=100_000),
        catalog=catalog,
        effective_at="2026-08-21",
        service_tier="fast",
    )
    assert fast.amount_usd == Decimal("0.4")


def test_deepseek_v4_flat_card_hands_over_to_the_scheduled_card(catalog: PricingCatalog):
    # DeepSeek moved to peak/off-peak billing at 16:00 UTC on 2026-08-16, which
    # opentine-pricing/1 could not express, so the flat cards were closed at
    # 2026-08-15. /2 carries a schedule, so the day after is priced again.
    usage = Usage(input=1_000_000, output=1_000_000)
    flat = bill("deepseek", "deepseek-v4-pro", usage, catalog=catalog, effective_at="2026-08-15")
    after = bill(
        "deepseek", "deepseek-v4-pro", usage, catalog=catalog, effective_at="2026-08-16T02:00:00Z"
    )
    assert flat.rate_card_id == "deepseek:deepseek-v4-pro:2026-07-14"
    assert flat.amount_usd == Decimal("1.305")
    assert flat.calculation.get("schedule_window") is None
    assert after.rate_card_id == "deepseek:deepseek-v4-pro:2026-08-16"
    assert after.status == "complete" and after.amount_usd == Decimal("5.28")


@pytest.mark.parametrize(
    ("moment", "card", "window", "pro", "flash"),
    [
        # 2026-08-24 is a Monday: 02:30 UTC is inside peak 01:00-04:00, 07:00
        # inside peak 06:00-10:00, and 04:00/12:00 are off-peak (half price).
        ("2026-08-24T02:30:00Z", "2026-08-23", "peak", "5.28", "1.76"),
        ("2026-08-24T07:00:00Z", "2026-08-23", "peak", "5.28", "1.76"),
        ("2026-08-24T04:00:00Z", "2026-08-23", "base", "2.64", "0.88"),
        ("2026-08-24T12:00:00Z", "2026-08-23", "base", "2.64", "0.88"),
        # Saturday 2026-08-29: off-peak all day under the weekend rule.
        ("2026-08-29T02:30:00Z", "2026-08-23", "base", "2.64", "0.88"),
        # The same clock time one week earlier, before the weekend rule took
        # effect, was still peak: that card scopes its window to every day.
        ("2026-08-22T02:30:00Z", "2026-08-16", "peak", "5.28", "1.76"),
    ],
)
def test_deepseek_peak_and_off_peak_rates_by_time_of_day(
    catalog: PricingCatalog, moment: str, card: str, window: str, pro: str, flash: str
):
    # Hand-computed from the published per-1M rates on a 1M-in/1M-out call:
    # pro peak 1.32 + 3.96, pro off-peak 0.66 + 1.98; flash peak 0.44 + 1.32,
    # flash off-peak 0.22 + 0.66.
    usage = Usage(input=1_000_000, output=1_000_000)
    for model, expected in (("deepseek-v4-pro", pro), ("deepseek-v4-flash", flash)):
        result = bill("deepseek", model, usage, catalog=catalog, effective_at=moment)
        assert result.rate_card_id == f"deepseek:{model}:{card}"
        assert result.amount_usd == Decimal(expected)
        assert result.calculation["schedule_window"] == window
        assert result.calculation["billed_at"] == moment.replace("Z", "+00:00")


def test_deepseek_scheduled_card_priced_from_a_bare_date_uses_base_rates(catalog: PricingCatalog):
    # A day is not an instant: with no time of day there is no window to select,
    # so the documented fallback is the card's base (off-peak) rates.
    usage = Usage(input=1_000_000, output=1_000_000)
    result = bill("deepseek", "deepseek-v4-pro", usage, catalog=catalog, effective_at="2026-08-24")
    assert result.rate_card_id == "deepseek:deepseek-v4-pro:2026-08-23"
    assert result.amount_usd == Decimal("2.64")
    assert result.calculation["schedule_window"] == "base"
    assert result.calculation["billed_at"] is None


def test_deepseek_aliases_reach_the_scheduled_flash_card(catalog: PricingCatalog):
    usage = Usage(input=1_000_000, output=1_000_000)
    for alias in ("deepseek-chat", "deepseek-reasoner"):
        peak = bill("deepseek", alias, usage, catalog=catalog, effective_at="2026-08-24T02:30:00Z")
        assert peak.rate_card_id == "deepseek:deepseek-v4-flash:2026-08-23"
        assert peak.amount_usd == Decimal("1.76")


@pytest.mark.parametrize(
    ("provider", "model", "card_prefix"),
    [
        ("kimi", "kimi-k2.6", "kimi:"),
        ("glm", "glm-5.2", "glm:"),
        ("xai", "grok-4.5", "xai:"),
        ("xai", "grok-4.20", "xai:grok-4.20"),
        ("mistral", "ministral-14b-2512", "mistral:ministral"),
        ("qwen", "qwen3.7-max", "qwen:"),
        ("groq", "qwen/qwen3-32b", "groq:"),
        ("together", "moonshotai/Kimi-K2.7-Code", "together:"),
        ("openrouter", "nousresearch/hermes-4-70b", "openrouter:"),
    ],
)
def test_requested_hosted_families_have_provider_scoped_prices(
    catalog: PricingCatalog, provider: str, model: str, card_prefix: str
):
    result = bill(
        provider,
        model,
        Usage(input=1_000_000, output=1_000_000),
        catalog=catalog,
        effective_at="2026-07-15",
    )
    assert result.status == "complete"
    assert result.rate_card_id and result.rate_card_id.startswith(card_prefix)
    assert result.amount_usd is not None


def test_current_deepseek_aliases_resolve_to_v4_flash(catalog: PricingCatalog):
    usage = Usage(input=1_000_000, output=1_000_000)
    legacy = bill("deepseek", "deepseek-chat", usage, catalog=catalog, effective_at="2026-04-23")
    gap = bill("deepseek", "deepseek-chat", usage, catalog=catalog, effective_at="2026-04-24")
    current = bill("deepseek", "deepseek-chat", usage, catalog=catalog, effective_at="2026-07-15")
    assert legacy.rate_card_id == "deepseek:deepseek-chat:legacy-2026-07"
    assert legacy.amount_usd == Decimal("0.70")
    assert gap.status == "unknown" and gap.rate_card_id is None
    assert current.rate_card_id == "deepseek:deepseek-v4-flash:2026-07-14"
    assert current.amount_usd == Decimal("0.42")


def test_current_together_cards_and_effective_transition(catalog: PricingCatalog):
    usage = Usage(input=1_000_000, output=1_000_000)
    legacy = bill(
        "together",
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        usage,
        catalog=catalog,
        effective_at="2026-05-28",
    )
    current = bill(
        "together",
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        usage,
        catalog=catalog,
        effective_at="2026-05-29",
    )
    kimi = bill(
        "together",
        "moonshotai/Kimi-K2.7-Code",
        Usage(input=1_000_000, cache_read=1_000_000, output=1_000_000),
        catalog=catalog,
        effective_at="2026-07-15",
    )
    assert legacy.amount_usd == Decimal("1.76")
    assert current.amount_usd == Decimal("2.08")
    assert kimi.amount_usd == Decimal("5.14")

    deprecated = bill(
        "together",
        "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        usage,
        catalog=catalog,
        effective_at="2026-07-16",
    )
    assert deprecated.status == "unknown" and deprecated.rate_card_id is None


def test_google_service_rates_and_audio_dimensions_are_exact(catalog: PricingCatalog):
    usage = google_usage(
        {
            "promptTokenCount": 1_000_000,
            "cachedContentTokenCount": 200_000,
            "candidatesTokenCount": 1_000_000,
            "promptTokensDetails": [{"modality": "AUDIO", "tokenCount": 600_000}],
            "cacheTokensDetails": [{"modality": "AUDIO", "tokenCount": 200_000}],
        }
    )
    assert usage.to_dict() == {
        "input": 400_000,
        "output": 1_000_000,
        "input_audio": 400_000,
        "cache_read_audio": 200_000,
        "total": 2_000_000,
    }
    standard = bill(
        "google", "gemini-3-flash-preview", usage, catalog=catalog, effective_at="2026-07-15"
    )
    batch = bill(
        "google",
        "gemini-3-flash-preview",
        usage,
        catalog=catalog,
        effective_at="2026-07-15",
        service_tier="batch",
    )
    flex = bill(
        "google",
        "gemini-3.5-flash",
        Usage(input=1_000_000, cache_read=1_000_000, output=1_000_000),
        catalog=catalog,
        effective_at="2026-07-15",
        service_tier="flex",
    )
    assert standard.amount_usd == Decimal("3.62")
    assert batch.amount_usd == Decimal("1.82")
    assert flex.amount_usd == Decimal("5.33")
    assert flex.calculation["service_rates_per_million"]["cache_read"] == "0.08"


def test_google_generate_content_rejects_unimplemented_service_transport():
    assert Google().name == "gemini-3.5-flash"
    with pytest.raises(ValueError, match="standard, flex, or priority"):
        Google(service_tier="batch")


def test_unknown_service_tier_has_no_false_known_subtotal(catalog: PricingCatalog):
    usage = Usage(input=1_000_000)
    unknown = bill(
        "openai",
        "gpt-5.6",
        usage,
        catalog=catalog,
        effective_at="2026-07-15",
        service_tier="experimental",
    )
    default = bill(
        "openai",
        "gpt-5.6",
        usage,
        catalog=catalog,
        effective_at="2026-07-15",
        service_tier="default",
    )
    assert unknown.status == "unknown" and unknown.known_subtotal_usd == 0
    assert default.status == "complete" and default.amount_usd == Decimal("10")


@pytest.mark.parametrize("value", [Decimal("-1"), Decimal("Infinity"), Decimal("NaN")])
def test_scalar_service_modifiers_are_finite_and_non_negative(value: Decimal):
    with pytest.raises(ValueError, match="finite and non-negative"):
        RateCard(
            "bad",
            "provider",
            "model",
            {"input": Decimal("1")},
            service_modifiers={"priority": value},
        )


def test_unknown_partial_dynamic_and_unmetered_are_distinct(catalog: PricingCatalog):
    unknown = bill("openai", "kimi-k2.6", Usage(input=10), catalog=catalog)
    dynamic = bill("nous", "Hermes-4-70B", Usage(input=10), catalog=catalog)
    dynamic_zero = bill("nous", "Hermes-4-70B", Usage(), catalog=catalog)
    local = bill("ollama", "qwen3", Usage(input=10), catalog=catalog, unmetered=True)
    partial = calculate(
        Usage(input=1_000_000, output=1_000_000),
        RateCard("test", "vendor", "model", {"input": Decimal("2")}),
    )
    assert unknown.status == "unknown" and unknown.amount_usd is None
    assert dynamic.status == "unknown" and dynamic.amount_usd is None
    assert dynamic_zero.status == "unknown" and dynamic_zero.amount_usd is None
    assert local.status == "unmetered" and local.amount_usd == 0
    assert partial.status == "partial" and partial.known_subtotal_usd == 2
    with pytest.raises(ValueError, match="finite and non-negative"):
        Usage(extra={"compute_seconds": Decimal("NaN")})
    with pytest.raises(ValueError, match="non-negative safe integer"):
        Usage(input=1.5)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="finite and non-negative"):
        RateCard("invalid", "vendor", "model", {"input": Decimal("NaN")})


def test_local_overlay_wins_without_mutating_signed_snapshot(catalog: PricingCatalog):
    local = PricingCatalog(
        "local",
        (RateCard("discount", "kimi", "kimi-k2.6", {"input": Decimal("0.1")}),),
        "local",
    )
    combined = catalog.overlay(local)
    result = bill("kimi", "kimi-k2.6", Usage(input=1_000_000), catalog=combined)
    assert result.rate_card_id == "discount"
    assert result.amount_usd == Decimal("0.1")
    assert catalog.lookup("kimi", "kimi-k2.6").id != "discount"


def test_run_manifest_pins_catalog_signature_and_calculation():
    class MeteredModel:
        name = "kimi-k2.6"
        supports_tools = True
        supports_thinking = True

        async def complete(self, messages, tools=None, system=None, temperature=0.0):
            return {
                "text": "done",
                "tool_calls": [],
                **metered_response("kimi", self.name, Usage(input=10, output=2)),
            }

    run = Agent(MeteredModel()).run_sync("go")
    pricing = run.manifest["pricing"]
    assert pricing["catalog_provenance"][0]["signature"]["algorithm"] == "ed25519"
    assert pricing["catalogs"][0]["catalog_id"] == pricing["catalog_id"]
    assert pricing["invocations"][0]["catalog_hash"] == pricing["catalog_hash"]
    assert pricing["rate_cards"]
    assert pricing["invocations"][0]["calculation"]["usage"]["input"] == 10


# --------------------------------------------------------------------------- #
# 0.8.1: the GLM China endpoint is unpriced, and now says so
# --------------------------------------------------------------------------- #


def test_glm_cn_miss_names_the_reason_and_the_remedy(catalog: PricingCatalog):
    # The catalog cards the international z.ai endpoint only, and its USD rates
    # are deliberately not reused for the China endpoint. The miss must not read
    # as a catalog gap: it has to name the endpoint and point at the overlay.
    result = bill("glm-cn", "glm-5.2", Usage(input=1_000, output=1_000), catalog=catalog)
    assert result.status == "unknown"
    assert result.amount_usd is None
    assert result.rate_card_id is None
    note = next(warning for warning in result.warnings if "glm-cn" in warning)
    assert "open.bigmodel.cn" in note
    assert "deliberately not applied" in note
    assert "overlay" in note
    # And the international provider is unaffected: it still prices exactly.
    priced = bill("glm", "glm-5.2", Usage(input=1_000_000, output=1_000_000), catalog=catalog)
    assert priced.status == "complete"
    assert priced.amount_usd == Decimal("5.80")
    assert not any("glm-cn" in warning for warning in priced.warnings)


def test_glm_cn_note_is_dropped_once_a_local_overlay_prices_the_run(catalog: PricingCatalog):
    # The note is advice about a missing card, so an overlay (or an explicit
    # rate override, its in-process equivalent) must silence it rather than
    # nag over a price the operator has supplied.
    result = bill(
        "glm-cn",
        "glm-5.2",
        Usage(input=1_000_000, output=1_000_000),
        catalog=catalog,
        rate_override={"input": "1.40", "output": "4.40"},
    )
    assert result.status == "complete"
    assert result.amount_usd == Decimal("5.80")
    assert not any("glm-cn" in warning for warning in result.warnings)


def test_a_china_region_glm_run_records_the_unpriced_note():
    # End to end through the adapter that chooses the provider string: a JWT
    # key routes to open.bigmodel.cn as provider "glm-cn".
    from opentine.models._compat_hosted import GLM

    adapter = GLM(api_key="id.secret")
    assert adapter._provider == "glm-cn"
    billing = metered_response(adapter._provider, "glm-5.2", Usage(input=1_000, output=1_000))[
        "billing"
    ]
    assert billing["status"] == "unknown" and billing["amount_usd"] is None
    assert any("glm-cn" in warning and "overlay" in warning for warning in billing["warnings"])


# --------------------------------------------------------------------------- #
# 0.8.1: Claude Fable 5.1, GPT-6 Astra, and the Qwen3.8 hosted pair
# --------------------------------------------------------------------------- #


def test_fable_5_1_cache_reads_use_the_model_specific_rate_not_the_family_rule(
    catalog: PricingCatalog,
):
    # Anthropic prices cache hits at 0.1x base input on every model EXCEPT
    # Fable 5.1 and Mythos 5.1, which are 0.025x. A family-wide 0.1x rule would
    # bill $1/MTok here; the card's published literal is $0.25/MTok and must win.
    usage = Usage(
        input=1_000_000,
        cache_read=1_000_000,
        cache_write_5m=1_000_000,
        cache_write_1h=1_000_000,
        output=1_000_000,
    )
    new = bill("anthropic", "claude-fable-5-1", usage, catalog=catalog, effective_at="2026-09-01")
    old = bill("anthropic", "claude-fable-5", usage, catalog=catalog, effective_at="2026-09-01")
    assert new.status == "complete"
    assert new.calculation["rates_per_million"]["cache_read"] == "0.25"
    assert old.calculation["rates_per_million"]["cache_read"] == "1"
    # Every other dimension is identical to Fable 5, so the whole difference is
    # the cache read: $93.50 - $0.75.
    assert new.amount_usd == Decimal("92.75")
    assert old.amount_usd == Decimal("93.50")
    assert new.amount_usd == old.amount_usd - Decimal("0.75")


def test_fable_5_1_has_batch_and_us_tiers_but_no_fast_mode(catalog: PricingCatalog):
    usage = Usage(
        input=1_000_000,
        cache_read=1_000_000,
        cache_write_5m=1_000_000,
        cache_write_1h=1_000_000,
        output=1_000_000,
    )
    kwargs = {"catalog": catalog, "effective_at": "2026-09-01"}
    assert bill("anthropic", "claude-fable-5-1", usage, service_tier="batch", **kwargs).amount_usd
    assert bill(
        "anthropic", "claude-fable-5-1", usage, service_tier="batch", **kwargs
    ).amount_usd == Decimal("46.375")
    assert bill(
        "anthropic", "claude-fable-5-1", usage, service_tier="us", **kwargs
    ).amount_usd == Decimal("102.025")
    # Fast mode covers Claude Opus 5 and Opus 4.8 only. Opus 5 prices it; Fable
    # 5.1 must stay visibly unknown rather than borrow the 2x.
    fast = bill("anthropic", "claude-fable-5-1", usage, service_tier="fast", **kwargs)
    assert fast.status == "unknown" and fast.amount_usd is None
    assert bill("anthropic", "claude-opus-5", usage, service_tier="fast", **kwargs).status == (
        "complete"
    )
    # Released 2026-09-01; nothing earlier is priced.
    assert (
        bill(
            "anthropic", "claude-fable-5-1", usage, catalog=catalog, effective_at="2026-08-31"
        ).status
        == "unknown"
    )


def test_gpt_6_astra_272k_threshold_reprices_the_whole_request(catalog: PricingCatalog):
    # "Prompts with more than 272K input tokens are priced at 2x input and cache
    # rates and 1.5x output for the full request" -- request-scoped, so the
    # multiplier applies to every token, not only to the ones above the line.
    at = {"catalog": catalog, "effective_at": "2026-09-03"}
    short = bill("openai", "gpt-6-astra", Usage(input=272_000, output=1_000_000), **at)
    long = bill("openai", "gpt-6-astra", Usage(input=273_000, output=1_000_000), **at)
    assert short.amount_usd == Decimal("52.72")  # 0.272 * 10 + 1 * 50
    assert short.calculation["context_rules"] == []
    # Not 52.72 + 1000 tokens at 2x: the whole 273K bills at $20 and the whole
    # 1M output at $75.
    assert long.amount_usd == Decimal("80.46")
    assert long.calculation["context_rules"] == ["over-272k"]
    # Compare numerically: the engine renders a multiplied rate as its Decimal
    # result, so 50 * 1.5 is "75.0" while 10 * 2 is "20" -- string equality here
    # pins a formatting artifact, not the price.
    assert Decimal(long.calculation["rates_per_million"]["input"]) == Decimal("20")
    assert Decimal(long.calculation["rates_per_million"]["output"]) == Decimal("75")


def test_gpt_6_astra_cache_dimensions_and_published_service_tiers(catalog: PricingCatalog):
    usage = Usage(
        input=1_000_000,
        cache_read=1_000_000,
        cache_write_5m=1_000_000,
        cache_write_1h=1_000_000,
        output=1_000_000,
    )
    at = {"catalog": catalog, "effective_at": "2026-09-03"}
    # 4M prompt tokens crosses 272K, so every rate is the long-context one:
    # 20 + 2 + 25 + 25 + 75.
    assert bill("openai", "gpt-6-astra", usage, **at).amount_usd == Decimal("147")
    small = Usage(input=100_000, output=100_000)
    base = bill("openai", "gpt-6-astra", small, **at)
    assert base.amount_usd == Decimal("6")  # 0.1 * 10 + 0.1 * 50
    assert bill("openai", "gpt-6-astra", small, service_tier="batch", **at).amount_usd == (
        Decimal("3")
    )
    assert bill("openai", "gpt-6-astra", small, service_tier="flex", **at).amount_usd == (
        Decimal("3")
    )
    assert bill("openai", "gpt-6-astra", small, service_tier="fast", **at).amount_usd == (
        Decimal("12")
    )
    # OpenAI publishes no priority price for this model, so it is not carded.
    priority = bill("openai", "gpt-6-astra", small, service_tier="priority", **at)
    assert priority.status == "unknown" and priority.amount_usd is None
    assert (
        bill("openai", "gpt-6-astra", small, catalog=catalog, effective_at="2026-09-02").status
        == "unknown"
    )


@pytest.mark.parametrize(
    ("model", "implicit", "explicit"),
    [
        ("qwen3.8-max", "10.75", "10.67"),
        ("qwen3.8-27b", "4.225", "4.175"),
        ("qwen3.8-flash", "0.836", "0.836"),
    ],
)
def test_qwen38_hosted_cards_keep_implicit_and_explicit_cache_tiers(
    catalog: PricingCatalog, model: str, implicit: str, explicit: str
):
    usage = Usage(
        input=1_000_000,
        cache_read=1_000_000,
        cache_write_5m=1_000_000,
        output=1_000_000,
    )
    at = {"catalog": catalog, "effective_at": "2026-09-04"}
    assert bill("qwen", model, usage, **at).amount_usd == Decimal(implicit)
    tiered = bill("qwen", model, usage, service_tier="explicit_cache", **at)
    assert tiered.amount_usd == Decimal(explicit)


def test_qwen38_flash_next_is_held_and_never_aliased_onto_flash(catalog: PricingCatalog):
    # qwencloud.com/models/qwen3.8-flash-next is a 404 and the model is
    # open-weight only; qwen3.8-flash is a distinct, hosted, priced model.
    usage = Usage(input=1_000_000, output=1_000_000)
    at = {"catalog": catalog, "effective_at": "2026-09-04"}
    held = bill("qwen", "qwen3.8-flash-next", usage, **at)
    assert held.status == "unknown"
    assert held.amount_usd is None
    assert held.rate_card_id is None
    priced = bill("qwen", "qwen3.8-flash", usage, **at)
    assert priced.status == "complete"
    assert priced.amount_usd == Decimal("0.62")  # 0.15 in + 0.47 out
    assert "flash-next" not in (priced.rate_card_id or "")
