"""The 2026-10-20 catalog refresh: Mistral Large 4 list price, MiniMax M3.1 Flash, Gemini Omni."""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from opentine.billing import Usage, bill
from opentine.billing.catalog import BUNDLED_CATALOG, PricingCatalog

MILLION_IN = Usage(input=1_000_000)
MILLION_OUT = Usage(output=1_000_000)
MILLION_CACHED = Usage(cache_read=1_000_000)


@pytest.fixture(scope="module")
def catalog():
    return PricingCatalog.load(BUNDLED_CATALOG, require_signature=True)


def _usd(catalog, provider, model, when, usage, tier=None):
    result = bill(provider, model, usage, effective_at=when, service_tier=tier, catalog=catalog)
    assert result.status == "complete", (provider, model, when, result.status)
    return Decimal(result.amount_usd)


def test_the_refresh_is_signed_and_dated(catalog):
    raw = json.loads(BUNDLED_CATALOG.read_text(encoding="utf-8"))
    assert catalog.signed and raw["generated_at"] >= "2026-10-20T00:00:00Z"
    assert raw["verified_at"] >= "2026-10-20"
    assert len(raw["cards"]) >= 224  # 194 + 30 media cards (test_multimodal_0_11); 0.12 adds more


def test_mistral_large_4_switches_from_the_launch_sale_to_list_price(catalog):
    assert _usd(catalog, "mistral", "mistral-large-4", "2026-10-19", MILLION_IN) == Decimal("0.68")
    assert _usd(catalog, "mistral", "mistral-large-4", "2026-10-20", MILLION_IN) == Decimal("1.36")
    assert _usd(catalog, "mistral", "mistral-large-4", "2026-10-20", MILLION_CACHED) == Decimal(
        "0.14"
    )
    assert _usd(catalog, "mistral", "mistral-large-4", "2026-10-20", MILLION_OUT) == Decimal("4.18")
    assert _usd(catalog, "mistral", "mistral-large-4-0", "2026-11-01", MILLION_IN) == Decimal(
        "1.36"
    )


def test_minimax_m3_1_flash_is_priced_from_its_release_day(catalog):
    assert _usd(catalog, "minimax", "MiniMax-M3.1-Flash", "2026-10-19", MILLION_IN) == Decimal(
        "0.15"
    )
    assert _usd(catalog, "minimax", "MiniMax-M3.1-Flash", "2026-10-19", MILLION_CACHED) == Decimal(
        "0.015"
    )
    assert _usd(catalog, "minimax", "MiniMax-M3.1-Flash", "2026-10-19", MILLION_OUT) == Decimal(
        "0.60"
    )
    assert catalog.lookup("minimax", "MiniMax-M3.1-Flash", effective_at="2026-10-18") is None


def test_minimax_m3_priority_tier_is_one_and_a_half_times_standard(catalog):
    small = Usage(input=100_000)  # under the 512k context threshold
    assert _usd(catalog, "minimax", "MiniMax-M3", "2026-10-20", small) == Decimal("0.030")
    assert _usd(catalog, "minimax", "MiniMax-M3", "2026-10-20", small, "priority") == Decimal(
        "0.045"
    )


def test_gemini_omni_flash_ga_and_the_preview_window(catalog):
    assert _usd(catalog, "google", "gemini-omni-1.1-flash", "2026-10-20", MILLION_IN) == Decimal(
        "1.50"
    )
    assert _usd(catalog, "google", "gemini-omni-1.1-flash", "2026-10-20", MILLION_OUT) == Decimal(
        "9.00"
    )
    assert _usd(
        catalog, "google", "gemini-omni-flash-preview", "2026-10-21", MILLION_IN
    ) == Decimal("1.50")
    assert catalog.lookup("google", "gemini-omni-flash-preview", effective_at="2026-10-22") is None


def test_deepseek_flash_records_the_1017_version_at_unchanged_prices(catalog):
    card = catalog.lookup("deepseek", "deepseek-flash", effective_at="2026-10-20")
    assert card.metadata["model_version"] == "DeepSeek-V4.1-Flash-1017"


def test_uncarded_announcements_stay_unknown(catalog):
    # Muse Spark Open is weights-only (no Model API price); Fable 5.5 is unpriced.
    assert catalog.lookup("meta", "muse-spark-open", effective_at="2026-10-20") is None
    assert catalog.lookup("anthropic", "claude-fable-5-5", effective_at="2026-10-20") is None
