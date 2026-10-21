"""0.11 multimodal billing: image, video, audio, speech, request and omni pricing.

Wire fixtures follow the documented response schemas:

* Gemini ``usageMetadata`` with ``promptTokensDetails`` / ``candidatesTokensDetails``
  (``ModalityTokenCount``): https://ai.google.dev/api/generate-content#UsageMetadata
* OpenAI Chat Completions ``usage.prompt_tokens_details.audio_tokens`` and
  ``completion_tokens_details.audio_tokens``:
  https://platform.openai.com/docs/api-reference/chat/object
* Prices: https://ai.google.dev/gemini-api/docs/pricing and
  https://developers.openai.com/api/docs/pricing (checked 2026-10-20).
"""

from __future__ import annotations

import json
from datetime import date
from decimal import Decimal

import pytest

from opentine._pricing_record import bill_record
from opentine.billing import (
    BUNDLED_CATALOG,
    CatalogError,
    PricingCatalog,
    RateCard,
    Usage,
    bill,
    load_catalogs,
)
from opentine.billing._catalog_verify import catalog_hash
from opentine.billing._media import media_usage
from opentine.models._usage import google_usage, openai_usage
from opentine.trace._otel_usage import otel_usage, usage_attributes

WHEN = "2026-10-21"


@pytest.fixture(scope="module")
def catalog():
    return load_catalogs()


def _card(**overrides):
    data = {"id": "x:m:1", "provider": "x", "model": "m", "rates": {"input": "1", "output": "2"}}
    data.update(overrides)
    return RateCard.from_dict(data)


def _price(card, usage, **kwargs):
    return bill("x", "m", usage, catalog=PricingCatalog("t", (card,), "t"), **kwargs)


# --------------------------------------------------------------------------- #
# per-unit dimensions and explicit same-rate aliasing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("units", "dimension", "count", "rate", "expected"),
    [
        ({"images": "image"}, "images", 3, "0.04", "0.12"),
        ({"video_seconds:720p": "second"}, "video_seconds:720p", 8, "0.10", "0.80"),
        ({"audio_minutes": "minute"}, "audio_minutes", 10, "0.006", "0.060"),
        ({"tts_characters": "character"}, "tts_characters", 1000, "0.000015", "0.015"),
        ({"requests": "request"}, "requests", 2, "0.08", "0.16"),
    ],
)
def test_a_per_unit_dimension_is_priced_per_unit_not_per_million(
    units, dimension, count, rate, expected
):
    card = _card(rates={dimension: rate}, units=units)
    result = _price(card, Usage(extra={dimension: count}))
    assert result.status == "complete"
    assert result.amount_usd == Decimal(expected)
    assert result.calculation["units"] == units


def test_media_usage_names_every_variant_in_the_canonical_dimensions():
    usage = media_usage(
        images={"1024x1024:high": 2, "512x512:low": 1},
        video_seconds={"1080p": 4.5},
        audio_input_seconds=3,
        tts_characters=40,
        requests=1,
        tokens={"input": 10, "output_image": 1120},
    )
    assert usage.input == 10
    assert dict(usage.extra) == {
        "images:1024x1024:high": 2,
        "images:512x512:low": 1,
        "video_seconds:1080p": Decimal("4.5"),
        "audio_input_seconds": 3,
        "tts_characters": 40,
        "requests": 1,
        "output_image": 1120,
    }


def test_a_media_dimension_without_a_rate_is_partial_never_the_text_rate():
    result = _price(_card(), Usage(input=1_000_000, extra={"output_image": 1_000_000}))
    assert result.status == "partial"
    assert result.amount_usd is None
    assert "missing rates for usage dimensions: output_image" in result.warnings[0]


def test_same_rate_as_is_explicit_and_uses_the_named_rate():
    card = _card(same_rate_as={"input_video": "input"})
    result = _price(card, Usage(extra={"input_video": 2_000_000}))
    assert result.status == "complete" and result.amount_usd == Decimal("2")
    assert result.calculation["same_rate_as"] == {"input_video": "input"}


def test_a_service_modifier_for_the_base_dimension_applies_to_its_alias():
    card = _card(
        same_rate_as={"input_video": "input"},
        service_modifiers={"batch": {"input": "0.5", "output": "0.5"}},
    )
    result = _price(card, Usage(extra={"input_video": 1_000_000}), service_tier="batch")
    assert result.amount_usd == Decimal("0.5")


@pytest.mark.parametrize(
    "fields",
    [
        {"units": {"images": "pixel"}},
        {"same_rate_as": {"input_video": "input_video"}},
        {"same_rate_as": {"a": "b", "b": "input"}},
        {"units": {"images": "image"}, "same_rate_as": {"images": "input"}},
        # A variant inherits its family's unit, so this joins per-image to per-million.
        {"units": {"images": "image"}, "same_rate_as": {"images:hd": "input"}},
        {"same_rate_as": {"images:hd": "input"}},
        {"units": ["images"]},
    ],
)
def test_malformed_media_fields_are_refused(fields):
    with pytest.raises(ValueError):
        _card(**fields)


def test_a_card_without_media_fields_serializes_exactly_as_before():
    card = _card()
    assert "units" not in card.to_dict() and "same_rate_as" not in card.to_dict()
    media = _card(rates={"images": "0.04"}, units={"images": "image"})
    assert RateCard.from_dict(media.to_dict()) == media


# --------------------------------------------------------------------------- #
# catalog schema gate
# --------------------------------------------------------------------------- #


def _catalog_file(tmp_path, schema, card):
    data = {"schema": schema, "cards": [card]}
    data["catalog_id"] = f"sha256:{catalog_hash(data)}"
    path = tmp_path / "pricing.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


MEDIA_CARD = {
    "id": "x:img:1",
    "provider": "x",
    "model": "img",
    "rates": {"images": "0.04"},
    "units": {"images": "image"},
}


@pytest.mark.parametrize("schema", ["opentine-pricing/1", "opentine-pricing/2"])
def test_media_fields_in_an_older_schema_are_refused(tmp_path, schema):
    # A 0.10 reader would take 0.04 per *million* images; such a file must not
    # look like an ordinary /1 or /2 catalog.
    with pytest.raises(CatalogError, match="opentine-pricing/3"):
        PricingCatalog.load(_catalog_file(tmp_path, schema, MEDIA_CARD), require_signature=False)


def test_a_schema_3_catalog_with_media_cards_loads(tmp_path):
    path = _catalog_file(tmp_path, "opentine-pricing/3", MEDIA_CARD)
    loaded = PricingCatalog.load(path, require_signature=False)
    assert loaded.cards[0].units == {"images": "image"}


def test_the_bundled_catalog_is_schema_3_signed_and_carries_media_cards(catalog):
    raw = json.loads(BUNDLED_CATALOG.read_text(encoding="utf-8"))
    assert raw["schema"] == "opentine-pricing/3"
    bundled = PricingCatalog.load(BUNDLED_CATALOG)
    assert bundled.signed
    assert any(card.units for card in bundled.cards)
    assert any(card.same_rate_as for card in bundled.cards)


# --------------------------------------------------------------------------- #
# bundled media cards
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("provider", "model", "usage", "expected", "tier"),
    [
        # 8 s of 720p video at 5,792 tokens/s, $17.50/M, plus $1.50/M video input.
        (
            "google",
            "gemini-omni-1.1-flash",
            Usage(extra={"output_video": 5792 * 8, "input_video": 1_000_000}),
            "2.31088",
            None,
        ),
        # One 1K image: 1,120 tokens at $30/M (Standard), $15/M (Batch).
        ("google", "gemini-nano-banana-2.1", Usage(extra={"output_image": 1120}), "0.0336", None),
        (
            "google",
            "gemini-nano-banana-2.1",
            Usage(extra={"output_image": 1120}),
            "0.0168",
            "batch",
        ),
        ("google", "gemini-3.1-flash-image", Usage(extra={"output_image": 1120}), "0.0672", None),
        ("google", "gemini-3.8-flash-tts", Usage(extra={"output_audio": 1_000_000}), "9", None),
        (
            "google",
            "gemini-3.8-live",
            Usage(extra={"input_audio": 1_000_000, "output_audio": 1_000_000}),
            "15",
            None,
        ),
        ("google", "lyria-3.5", media_usage(requests=1), "0.08", None),
        ("openai", "tts-1", media_usage(tts_characters=1_000_000), "15", None),
        ("openai", "whisper-1", Usage(extra={"audio_minutes": 10}), "0.06", None),
        (
            "openai",
            "gpt-realtime",
            Usage(extra={"input_audio": 1_000_000, "output_audio": 1_000_000}),
            "96",
            None,
        ),
        (
            "openai",
            "gpt-image-1",
            Usage(input=1_000_000, extra={"input_image": 1_000_000, "output_image": 1_000_000}),
            "55",
            None,
        ),
    ],
)
def test_bundled_media_cards_price_the_published_rates(
    catalog, provider, model, usage, expected, tier
):
    result = bill(provider, model, usage, catalog=catalog, effective_at=WHEN, service_tier=tier)
    assert result.status == "complete", result.warnings
    assert result.amount_usd == Decimal(expected)


def test_gemini_tts_doubles_on_the_published_2027_date(catalog):
    usage = Usage(extra={"output_audio": 1_000_000})
    late = bill("google", "gemini-3.8-flash-tts", usage, catalog=catalog, effective_at="2027-01-02")
    assert late.amount_usd == Decimal("18")


def test_post_hoc_pricing_bills_recorded_media_dimensions(catalog):
    result = bill_record(
        "google",
        "gemini-omni-1.1-flash",
        {"input": 1000, "output_video": 46336},
        catalog=catalog,
        when=date(2026, 10, 21),
    )
    assert result.status == "complete"
    assert result.amount_usd == Decimal("0.81238")


# --------------------------------------------------------------------------- #
# adapters
# --------------------------------------------------------------------------- #


def test_gemini_output_modalities_are_split_from_text_output():
    usage = google_usage(
        {
            "promptTokenCount": 100,
            "candidatesTokenCount": 1300,
            "totalTokenCount": 1400,
            "promptTokensDetails": [{"modality": "TEXT", "tokenCount": 100}],
            "candidatesTokensDetails": [
                {"modality": "TEXT", "tokenCount": 180},
                {"modality": "IMAGE", "tokenCount": 1120},
            ],
        }
    )
    assert usage.output == 180
    assert usage.extra["output_image"] == 1120


def test_gemini_video_and_audio_output_are_split():
    usage = google_usage(
        {
            "promptTokenCount": 10,
            "candidatesTokenCount": 5800,
            "candidatesTokensDetails": [
                {"modality": "VIDEO", "tokenCount": 5792},
                {"modality": "AUDIO", "tokenCount": 8},
            ],
        }
    )
    assert usage.output == 0
    assert usage.extra["output_video"] == 5792 and usage.extra["output_audio"] == 8


def test_gemini_text_only_usage_is_unchanged():
    usage = google_usage(
        {
            "promptTokenCount": 10,
            "candidatesTokenCount": 20,
            "candidatesTokensDetails": [{"modality": "TEXT", "tokenCount": 20}],
        }
    )
    assert usage.output == 20 and not usage.extra


def test_gemini_output_modalities_larger_than_the_total_are_refused():
    with pytest.raises(ValueError, match="output modalities"):
        google_usage(
            {
                "candidatesTokenCount": 10,
                "candidatesTokensDetails": [{"modality": "IMAGE", "tokenCount": 11}],
            }
        )


def test_openai_audio_tokens_are_split_from_text_tokens():
    usage = openai_usage(
        {
            "prompt_tokens": 1000,
            "completion_tokens": 500,
            "total_tokens": 1500,
            "prompt_tokens_details": {"cached_tokens": 100, "audio_tokens": 600},
            "completion_tokens_details": {"reasoning_tokens": 0, "audio_tokens": 400},
        }
    )
    assert (usage.input, usage.cache_read, usage.output) == (300, 100, 100)
    assert dict(usage.extra) == {"input_audio": 600, "output_audio": 400}


def test_openai_text_usage_without_media_fields_is_unchanged():
    usage = openai_usage(
        {
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "prompt_tokens_details": {"cached_tokens": 0, "audio_tokens": 0},
            "completion_tokens_details": {"reasoning_tokens": 2, "audio_tokens": 0},
        }
    )
    assert (usage.input, usage.output, usage.reasoning) == (10, 3, 2) and not usage.extra


def test_openai_media_counts_larger_than_their_bucket_are_bounded():
    usage = openai_usage(
        {
            "prompt_tokens": 100,
            "completion_tokens": 10,
            "prompt_tokens_details": {"cached_tokens": 90, "audio_tokens": 50},
        }
    )
    assert usage.input == 0 and usage.extra["input_audio"] == 10


# --------------------------------------------------------------------------- #
# OpenTelemetry
# --------------------------------------------------------------------------- #


def test_modality_counters_round_trip_through_export_and_import():
    usage = {
        "input": 100,
        "output": 20,
        "cache_read": 10,
        "input_audio": 30,
        "output_image": 50,
        "output_video": 7,
        "reasoning": 5,
    }
    attributes = usage_attributes(usage, {})
    assert attributes["gen_ai.usage.image.output_tokens"] == 50
    assert attributes["gen_ai.usage.input_tokens"] == 140
    assert "opentine.usage" not in attributes
    assert otel_usage(dict(attributes))[0] == usage


def test_imported_modality_counters_come_out_of_their_totals():
    imported, _ = otel_usage(
        {
            "gen_ai.usage.input_tokens": 100,
            "gen_ai.usage.output_tokens": 1200,
            "gen_ai.usage.image.output_tokens": 1120,
            "gen_ai.usage.audio.input_tokens": 40,
        }
    )
    assert imported == {"input": 60, "output": 80, "output_image": 1120, "input_audio": 40}


# --------------------------------------------------------------------------- #
# per-unit dimensions are never priced per million (audit 0.11 #7)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "rates",
    [
        {"input": "1", "images": "0.04"},
        {"input": "1", "images:1024x1024": "0.04"},
        {"input": "1", "audio_minutes": "0.006"},
        {"input": "1", "tts_characters": "0.000015"},
        {"input": "1", "requests": "0.01"},
    ],
)
def test_a_per_unit_rate_without_its_unit_is_refused_at_load(rates):
    with pytest.raises(ValueError, match="without a unit"):
        RateCard.from_dict({"id": "x:m:1", "provider": "x", "model": "m", "rates": rates})


def test_a_variant_is_priced_in_the_unit_of_its_family():
    card = _card(rates={"images:1024x1024": "0.04"}, units={"images": "image"})
    priced = _price(card, media_usage(images={"1024x1024": 2}))
    assert priced.status == "complete"
    assert priced.amount_usd == Decimal("0.08")


def test_resolve_rate_treats_a_unitless_per_unit_dimension_as_missing():
    from opentine.billing._media import resolve_rate

    class Bare:  # a card that slipped past validation (or a hand-built one)
        units: dict = {}
        same_rate_as: dict = {}

    for dimension in ("images", "images:512x512", "video_seconds:720p", "requests"):
        rate, _, _ = resolve_rate(Bare(), {dimension: Decimal("1")}, dimension)
        assert rate is None, dimension


@pytest.mark.parametrize("schema", ["opentine-pricing/1", "opentine-pricing/2"])
@pytest.mark.parametrize("name", ["images", "images:256x256", "audio_minutes", "requests"])
def test_per_unit_rate_names_in_an_older_schema_are_refused(tmp_path, schema, name):
    card = {"id": "x:m:1", "provider": "x", "model": "m", "rates": {"input": "1", name: "0.04"}}
    with pytest.raises(CatalogError, match="opentine-pricing/3"):
        PricingCatalog.load(_catalog_file(tmp_path, schema, card), require_signature=False)


@pytest.mark.parametrize(
    ("attributes", "expected"),
    [
        (  # cached media: the image tokens overlap the cache read
            {
                "gen_ai.usage.input_tokens": 1000,
                "gen_ai.usage.cache_read.input_tokens": 800,
                "gen_ai.usage.image.input_tokens": 500,
            },
            {"input": 0, "cache_read": 800, "input_image": 200},
        ),
        (  # several modalities against a small total
            {
                "gen_ai.usage.input_tokens": 100,
                "gen_ai.usage.image.input_tokens": 60,
                "gen_ai.usage.audio.input_tokens": 70,
            },
            {"input": 0, "input_image": 60, "input_audio": 40},
        ),
        (  # a consistent breakdown is carved out exactly
            {
                "gen_ai.usage.input_tokens": 1000,
                "gen_ai.usage.image.input_tokens": 300,
                "gen_ai.usage.output_tokens": 50,
                "gen_ai.usage.audio.output_tokens": 20,
            },
            {"input": 700, "input_image": 300, "output": 30, "output_audio": 20},
        ),
    ],
)
def test_otel_modality_counters_never_bill_more_than_the_reported_total(attributes, expected):
    usage, attrs = otel_usage(dict(attributes))
    assert usage == expected
    inputs = sum(v for k, v in usage.items() if k == "input" or k.startswith(("input_", "cache_")))
    assert inputs == attributes["gen_ai.usage.input_tokens"]
    consistent = usage.get("input", 0) > 0
    assert bool(attrs.get("opentine.import_warnings")) != consistent


@pytest.mark.parametrize(
    "usage",
    [
        {"input": 700, "input_image": 300, "output": 30, "output_audio": 20},
        {"input": 0, "cache_read": 800, "input_image": 200},
        {"input": 5, "input_image": 10, "input_audio": 7, "input_video": 3, "output_image": 9},
    ],
)
def test_otel_modality_usage_round_trips_through_export(usage):
    exported = usage_attributes(usage, {})
    read_back, _ = otel_usage(dict(exported))
    assert read_back == usage
