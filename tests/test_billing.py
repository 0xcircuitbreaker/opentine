"""Golden tests for provider-neutral, effective-dated billing."""

from __future__ import annotations

from decimal import Decimal

import pytest

from opentine.billing import PricingCatalog, RateCard, Usage, bill, calculate, load_catalogs
from opentine.billing.catalog import BUNDLED_CATALOG
from opentine.models._usage import metered_response
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
        ("glm", "glm-5.1", "glm:"),
        ("xai", "grok-4.5", "xai:"),
        ("mistral", "ministral-3-14b", "mistral:ministral"),
        ("qwen", "qwen3.7-max", "qwen:"),
        ("groq", "qwen/qwen3-32b", "groq:"),
        ("together", "moonshotai/Kimi-K2.6", "together:"),
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
        effective_at="2026-07-14",
    )
    assert result.status == "complete"
    assert result.rate_card_id and result.rate_card_id.startswith(card_prefix)
    assert result.amount_usd is not None


def test_unknown_partial_dynamic_and_unmetered_are_distinct(catalog: PricingCatalog):
    unknown = bill("openai", "kimi-k2.6", Usage(input=10), catalog=catalog)
    dynamic = bill("nous", "Hermes-4-70B", Usage(input=10), catalog=catalog)
    local = bill("ollama", "qwen3", Usage(input=10), catalog=catalog, unmetered=True)
    partial = calculate(
        Usage(input=1_000_000, output=1_000_000),
        RateCard("test", "vendor", "model", {"input": Decimal("2")}),
    )
    assert unknown.status == "unknown" and unknown.amount_usd is None
    assert dynamic.status == "unknown" and dynamic.amount_usd is None
    assert local.status == "unmetered" and local.amount_usd == 0
    assert partial.status == "partial" and partial.known_subtotal_usd == 2
    with pytest.raises(ValueError, match="finite and non-negative"):
        Usage(extra={"compute_seconds": Decimal("NaN")})


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
    assert pricing["rate_cards"]
    assert pricing["invocations"][0]["calculation"]["usage"]["input"] == 10
