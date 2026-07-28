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


def test_sonnet_5_introductory_rate_transition(catalog: PricingCatalog):
    usage = Usage(input=1_000_000, output=1_000_000)
    intro = bill("anthropic", "claude-sonnet-5", usage, catalog=catalog, effective_at="2026-08-31")
    standard = bill(
        "anthropic", "claude-sonnet-5", usage, catalog=catalog, effective_at="2026-09-01"
    )
    assert intro.rate_card_id == "anthropic:claude-sonnet-5:intro"
    assert intro.amount_usd == Decimal("12")
    assert standard.rate_card_id == "anthropic:claude-sonnet-5:standard"
    assert standard.amount_usd == Decimal("18")


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
