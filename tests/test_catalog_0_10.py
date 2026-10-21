"""The 2026-10-15 catalog refresh: new models, corrected windows, and cloud namespaces."""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from opentine.billing import Usage, bill
from opentine.billing.catalog import BUNDLED_CATALOG, PricingCatalog

MILLION = Usage(input=1_000_000)
#: Under every context threshold in the catalog (OpenAI 272K, Haiku 5.5 100K).
SMALL = Usage(input=100_000)


@pytest.fixture(scope="module")
def catalog():
    return PricingCatalog.load(BUNDLED_CATALOG, require_signature=True)


def _price(catalog, provider, model, when, usage=MILLION, tier=None):
    result = bill(provider, model, usage, effective_at=when, service_tier=tier, catalog=catalog)
    return result.status, (Decimal(result.amount_usd) if result.amount_usd is not None else None)


def test_the_refresh_is_signed_and_newer_than_every_earlier_release(catalog):
    raw = json.loads(BUNDLED_CATALOG.read_text(encoding="utf-8"))
    assert catalog.signed and raw["generated_at"] >= "2026-10-15T00:00:00Z"
    assert raw["verified_at"] >= "2026-10-15"
    for card in raw["cards"]:
        assert card["source_urls"] and card["verified_at"], card["id"]


@pytest.mark.parametrize(
    "provider",
    ["meta", "minimax", "stepfun", "xiaomi", "fireworks", "bedrock", "vertex", "foundry"],
)
def test_new_provider_namespaces_have_cards(catalog, provider):
    assert any(card.provider == provider for card in catalog.cards)


def test_gemini_4_argon_introductory_then_published_price(catalog):
    assert _price(catalog, "google", "gemini-4-argon", "2026-10-13") == ("complete", Decimal("2"))
    assert _price(catalog, "google", "gemini-4-argon", "2026-11-30") == ("complete", Decimal("2"))
    assert _price(catalog, "google", "gemini-4-argon", "2026-12-01") == ("complete", Decimal("4"))
    assert _price(catalog, "google", "gemini-4-argon", "2026-10-15", tier="priority") == (
        "complete",
        Decimal("3.6"),
    )
    assert _price(catalog, "google", "gemini-4-argon", "2026-10-12")[0] == "unknown"


def test_gemini_3_5_flash_window_starts_at_ga_and_closes_when_rerouted(catalog):
    assert _price(catalog, "google", "gemini-3.5-flash", "2026-05-19") == (
        "complete",
        Decimal("1.5"),
    )
    assert _price(catalog, "google", "gemini-3.5-flash", "2026-10-07") == (
        "complete",
        Decimal("1.5"),
    )
    # Routed to gemini-3.6-flash from 2026-10-08: never billed at the retired 2x rate.
    assert _price(catalog, "google", "gemini-3.5-flash", "2026-10-08")[0] == "unknown"


def test_mistral_large_4_launch_sale_is_carded_for_two_weeks_only(catalog):
    usage = Usage(input=1_000_000, output=1_000_000)
    assert _price(catalog, "mistral", "mistral-large-4", "2026-10-06", usage) == (
        "complete",
        Decimal("2.77"),
    )
    # The 2026-10-20 refresh cards the list price that follows the sale.
    assert _price(catalog, "mistral", "mistral-large-4", "2026-10-20", usage) == (
        "complete",
        Decimal("5.54"),
    )


@pytest.mark.parametrize(
    ("model", "when"),
    [
        ("meta-llama/Llama-3.3-70B-Instruct-Turbo", "2026-10-22"),
        ("deepseek-ai/DeepSeek-V4-Flash-0731", "2026-10-22"),
    ],
)
def test_together_scheduled_removals_close_the_day_before(catalog, model, when):
    assert _price(catalog, "together", model, "2026-10-21")[0] == "complete"
    assert _price(catalog, "together", model, when)[0] == "unknown"


def test_together_glm_5_1_window_is_its_serverless_life(catalog):
    cached = Usage(input=1_000_000, cache_read=1_000_000)
    assert _price(catalog, "together", "zai-org/GLM-5.1", "2026-04-07")[0] == "unknown"
    assert _price(catalog, "together", "zai-org/GLM-5.1", "2026-05-01") == (
        "complete",
        Decimal("1.40"),
    )
    assert _price(catalog, "together", "zai-org/GLM-5.1", "2026-06-15", cached) == (
        "complete",
        Decimal("1.66"),
    )
    assert _price(catalog, "together", "zai-org/GLM-5.1", "2026-07-14")[0] == "unknown"


def test_removed_and_backdated_hosted_cards(catalog):
    assert _price(catalog, "openrouter", "nousresearch/hermes-4-70b", "2026-10-15")[0] == "unknown"
    assert _price(catalog, "groq", "qwen/qwen3.8-27b", "2026-09-10") == (
        "complete",
        Decimal("0.80"),
    )
    assert _price(catalog, "groq", "openai/gpt-oss-120b", "2026-10-15") == (
        "complete",
        Decimal("0.15"),
    )


def test_qwen_max_implicit_cache_hits_are_twenty_percent_of_input(catalog):
    status, amount = _price(catalog, "qwen", "qwen-max", "2026-10-15", Usage(cache_read=1_000_000))
    assert (status, amount) == ("complete", Decimal("0.32"))


def test_older_openai_families_bill_their_own_fast_multiplier(catalog):
    assert _price(catalog, "openai", "gpt-5.5", "2026-10-15", SMALL, "fast") == (
        "complete",
        Decimal("1.25"),
    )
    assert _price(catalog, "openai", "gpt-5-mini", "2026-10-15", tier="fast") == (
        "complete",
        Decimal("0.45"),
    )
    assert _price(catalog, "openai", "gpt-5", "2026-10-15", SMALL, "fast") == (
        "complete",
        Decimal("0.25"),
    )
    assert _price(catalog, "openai", "gpt-5.4-nano", "2026-10-15", tier="fast")[0] == "unknown"


def test_openai_regional_processing_uplift(catalog):
    assert _price(catalog, "openai", "gpt-6.1-sol", "2026-10-15", SMALL, "regional") == (
        "complete",
        Decimal("0.22"),
    )
    # gpt-5.2 predates 2026-03-05, so no uplift is published for it.
    assert _price(catalog, "openai", "gpt-5.2", "2026-10-15", tier="regional")[0] == "unknown"


def test_cloud_claude_cards(catalog):
    assert _price(catalog, "bedrock", "anthropic.claude-opus-5-5", "2026-10-15") == (
        "complete",
        Decimal("4"),
    )
    assert _price(catalog, "bedrock", "claude-opus-5-5", "2026-10-15", tier="regional") == (
        "complete",
        Decimal("4.4"),
    )
    assert _price(catalog, "vertex", "claude-sonnet-5-5", "2026-10-15", tier="regional") == (
        "complete",
        Decimal("2.2"),
    )
    assert _price(catalog, "foundry", "claude-opus-5-5", "2026-10-15", tier="fast_us") == (
        "complete",
        Decimal("8.8"),
    )


def test_foundry_azure_openai_data_zones(catalog):
    assert _price(catalog, "foundry", "gpt-6-sol", "2026-10-15", SMALL, "us") == (
        "complete",
        Decimal("0.22"),
    )
    assert _price(catalog, "foundry", "gpt-6-sol", "2026-10-15", SMALL, "eu") == (
        "complete",
        Decimal("0.24"),
    )


def test_claude_5_family_cards_match_the_published_prices(catalog):
    expected = {
        "claude-opus-5-5": "0.4",
        "claude-sonnet-5-5": "0.2",
        "claude-haiku-5-5": "0.01",
        "claude-fable-5": "1",
        "claude-fable-5-1": "1",
    }
    for model, price in expected.items():
        assert _price(catalog, "anthropic", model, "2026-10-15", SMALL) == (
            "complete",
            Decimal(price),
        )


def test_unreleased_models_are_not_carded(catalog):
    # Claude Fable 5.5 has no published price; a card would be a guess.
    names = {name for card in catalog.cards for name in (card.model, *card.aliases)}
    assert "claude-fable-5-5" not in names
    assert not any(name.startswith("gpt-6.1-") and name != "gpt-6.1-sol" for name in names)
