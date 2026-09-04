"""WS4: time-of-day (peak/off-peak) pricing.

DeepSeek moved to peak/off-peak billing at 16:00 UTC on 2026-08-16, which
``opentine-pricing/1`` could not represent at all -- so 0.7.2 closed the
DeepSeek cards and every later run reported ``cost=unknown``. ``/2`` adds one
optional field, ``schedule``, and these tests pin both halves of the bargain:

* the new dimension prices DeepSeek correctly again, by the hour and by the
  weekday, from each step's *own* recorded instant; and
* it is additive by absence -- every card without a schedule, which is every
  card the catalog had before, prices to exactly the same cent as it did.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from decimal import Decimal

import pytest

from opentine import Run, StepKind
from opentine._graph_types import Step
from opentine._pricing_pass import price_run, price_steps
from opentine.billing import (
    BUNDLED_CATALOG,
    CatalogError,
    PricingCatalog,
    RateCard,
    Usage,
    bill,
    calculate,
    load_catalogs,
)
from opentine.billing.catalog import catalog_hash
from opentine.billing.types import as_datetime, billing_moment

MILLION = Usage(input=1_000_000, output=1_000_000)
#: A Monday, a Saturday, and the Sunday the weekend rule took effect.
MONDAY, SATURDAY = "2026-08-24", "2026-08-29"


@pytest.fixture(scope="module")
def catalog() -> PricingCatalog:
    return load_catalogs([BUNDLED_CATALOG])


def _peak_card(**overrides) -> RateCard:
    """A DeepSeek-shaped card: base rates are off-peak, one 2x peak window."""
    fields = {
        "id": "test:scheduled",
        "provider": "test",
        "model": "scheduled",
        "rates": {"input": "0.66", "output": "1.98"},
        "schedule": [
            {
                "id": "peak",
                "days": "weekday",
                "hours": [{"start": "01:00", "end": "04:00"}, {"start": "06:00", "end": "10:00"}],
                "rates": {"input": "1.32", "output": "3.96"},
            }
        ],
    }
    return RateCard(**{**fields, **overrides})


# --------------------------------------------------------------------------- #
# additive by absence: the 75 unscheduled cards must not move by a cent
# --------------------------------------------------------------------------- #


def test_every_bundled_card_without_a_schedule_prices_identically_at_every_hour(catalog):
    # The whole-catalog form of "a card without a schedule prices exactly as
    # today": for each one, the day and any instant within it agree, and no
    # schedule key appears in the calculation record at all.
    unscheduled = [card for card in catalog.cards if not card.schedule]
    assert len(unscheduled) == len(catalog.cards) - 6  # only the DeepSeek v4 cards are scheduled
    for card in unscheduled:
        day = max(card.effective_from, date(2026, 8, 24))
        baseline = calculate(MILLION, card, effective_at=day)
        assert "schedule_window" not in baseline.calculation
        assert "billed_at" not in baseline.calculation
        for hour in (2, 7, 15, 23):
            moment = datetime(day.year, day.month, day.day, hour, 30, tzinfo=UTC)
            priced = calculate(MILLION, card, effective_at=moment)
            assert priced.amount_usd == baseline.amount_usd, card.id
            assert priced.calculation == baseline.calculation, card.id


@pytest.mark.parametrize(
    ("provider", "model", "at", "expected"),
    [
        # gpt-5: input 1.25 + output 10 per million on a 1M/1M call.
        ("openai", "gpt-5", "2026-08-24", "11.25"),
        # deepseek-v4-flash before the cutover: 0.14 + 0.28, flat at every hour.
        ("deepseek", "deepseek-v4-flash", "2026-08-15", "0.42"),
    ],
)
def test_golden_unscheduled_prices_are_unchanged_by_the_new_dimension(
    catalog, provider, model, at, expected
):
    for when in (at, f"{at}T02:30:00Z", f"{at}T13:00:00Z"):
        result = bill(provider, model, MILLION, catalog=catalog, effective_at=when)
        assert result.amount_usd == Decimal(expected)


# --------------------------------------------------------------------------- #
# window selection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("moment", "window"),
    [
        (f"{MONDAY}T00:59:59Z", "base"),
        (f"{MONDAY}T01:00:00Z", "peak"),  # inclusive start
        (f"{MONDAY}T03:59:59Z", "peak"),
        (f"{MONDAY}T04:00:00Z", "base"),  # exclusive end
        (f"{MONDAY}T05:59:59Z", "base"),
        (f"{MONDAY}T06:00:00Z", "peak"),
        (f"{MONDAY}T10:00:00Z", "base"),
        (f"{SATURDAY}T02:30:00Z", "base"),  # weekday-scoped window, weekend moment
        (f"{SATURDAY}T02:30:00+00:00", "base"),
    ],
)
def test_window_edges_are_half_open_and_day_scoped(moment, window):
    result = calculate(MILLION, _peak_card(), effective_at=moment)
    assert result.calculation["schedule_window"] == window
    assert result.amount_usd == Decimal("5.28" if window == "peak" else "2.64")


def test_a_window_may_wrap_past_midnight():
    card = _peak_card(
        schedule=[
            {
                "id": "night",
                "days": "all",
                "hours": [{"start": "22:00", "end": "02:00"}],
                "rates": {"input": "1.32", "output": "3.96"},
            }
        ]
    )
    for moment, window in (
        (f"{MONDAY}T23:30:00Z", "night"),
        (f"{MONDAY}T01:59:00Z", "night"),
        (f"{MONDAY}T02:00:00Z", "base"),
        (f"{MONDAY}T12:00:00Z", "base"),
    ):
        assert (
            calculate(MILLION, card, effective_at=moment).calculation["schedule_window"] == window
        )


def test_weekend_scope_is_the_mirror_of_the_weekday_scope():
    card = _peak_card(
        schedule=[
            {
                "id": "weekend-surcharge",
                "days": "weekend",
                "hours": [{"start": "00:00", "end": "24:00"}],
                "rates": {"input": "1.32", "output": "3.96"},
            }
        ]
    )
    assert calculate(MILLION, card, effective_at=f"{SATURDAY}T12:00:00Z").amount_usd == Decimal(
        "5.28"
    )
    assert calculate(MILLION, card, effective_at=f"{MONDAY}T12:00:00Z").amount_usd == Decimal(
        "2.64"
    )


def test_a_local_time_is_placed_in_the_window_by_its_utc_hour():
    # 21:30 on Sunday in New York is 01:30 Monday UTC: a weekday peak hour. A
    # naive reading of either half would have called it an off-peak weekend.
    moment = datetime.fromisoformat("2026-08-23T21:30:00-04:00")
    result = calculate(MILLION, _peak_card(), effective_at=moment)
    assert result.calculation["schedule_window"] == "peak"
    assert result.calculation["billed_at"] == "2026-08-24T01:30:00+00:00"


def test_a_day_without_a_time_of_day_falls_back_to_base_rates():
    for value in (date(2026, 8, 24), MONDAY):
        result = calculate(MILLION, _peak_card(), effective_at=value)
        assert result.calculation["schedule_window"] == "base"
        assert result.calculation["billed_at"] is None
        assert result.amount_usd == Decimal("2.64")


def test_window_rates_override_only_the_dimensions_they_name():
    card = _peak_card(
        rates={"input": "0.66", "output": "1.98", "cache_read": "0.022"},
        schedule=[
            {
                "id": "peak",
                "days": "all",
                "hours": [{"start": "01:00", "end": "04:00"}],
                "rates": {"output": "3.96"},
            }
        ],
    )
    result = calculate(
        Usage(input=1_000_000, output=1_000_000, cache_read=1_000_000),
        card,
        effective_at=f"{MONDAY}T02:00:00Z",
    )
    assert result.calculation["rates_per_million"] == {
        "cache_read": "0.022",
        "input": "0.66",
        "output": "3.96",
    }


def test_an_explicit_service_tier_rate_still_wins_over_the_window():
    card = _peak_card(service_rates={"batch": {"output": "0.99"}})
    result = calculate(MILLION, card, effective_at=f"{MONDAY}T02:00:00Z", service_tier="batch")
    # input still takes the peak rate; output is the tier's explicit price.
    assert result.amount_usd == Decimal("2.31")


# --------------------------------------------------------------------------- #
# the billing moment: a date selects the card, a time selects the window
# --------------------------------------------------------------------------- #


def test_as_datetime_distinguishes_a_day_from_an_instant():
    assert as_datetime(date(2026, 8, 24)) is None
    assert as_datetime("2026-08-24") is None
    assert as_datetime("2026-08-24T02:30:00Z") == datetime(2026, 8, 24, 2, 30, tzinfo=UTC)
    assert as_datetime("2026-08-24 02:30:00") == datetime(2026, 8, 24, 2, 30, tzinfo=UTC)
    # naive is read as UTC rather than shifted, matching as_date's reading
    assert as_datetime(datetime(2026, 8, 24, 2, 30)) == datetime(2026, 8, 24, 2, 30, tzinfo=UTC)
    assert as_datetime("not-a-date") is None
    when, moment = billing_moment("2026-08-23T23:00:00-04:00")
    assert (when, moment.hour) == (date(2026, 8, 24), 3)


def test_billed_at_pins_the_window_without_moving_the_card(catalog):
    # `tine price --at DATE` asks what a run would cost under the cards
    # effective on DATE, while each step keeps the instant it really ran at.
    peak = bill(
        "deepseek",
        "deepseek-v4-pro",
        MILLION,
        catalog=catalog,
        effective_at="2026-08-19",
        billed_at=datetime(2026, 8, 24, 2, 30, tzinfo=UTC),
    )
    assert peak.rate_card_id == "deepseek:deepseek-v4-pro:2026-08-16"  # the --at card
    assert peak.effective_at == "2026-08-19"
    assert peak.amount_usd == Decimal("5.28")  # the step's own peak hour


# --------------------------------------------------------------------------- #
# the post-hoc pass prices every step at its own recorded timestamp
# --------------------------------------------------------------------------- #


def _step(identifier: str, moment: str | None) -> Step:
    return Step(
        id=identifier,
        parent_ids=[],
        kind=StepKind.model,
        inputs={},
        model_info="deepseek-v4-pro",
        provider="deepseek",
        usage={"input": 1_000_000, "output": 1_000_000},
        timestamp=0.0 if moment is None else datetime.fromisoformat(moment).timestamp(),
    )


def test_a_run_spanning_peak_and_off_peak_prices_each_step_at_its_own_hour(catalog):
    # The bug this closes: one `effective_at` for the whole run charged every
    # step the same rate, so a job that started in peak and finished after it
    # was billed entirely at one price.
    pricing = price_steps(
        [
            _step("peak", f"{MONDAY}T02:30:00+00:00"),
            _step("offpeak", f"{MONDAY}T12:00:00+00:00"),
            _step("weekend", f"{SATURDAY}T02:30:00+00:00"),
        ],
        catalog=catalog,
    )
    assert [step.known_subtotal_usd for step in pricing.steps] == [5.28, 2.64, 2.64]
    assert pricing.total_cost == pytest.approx(10.56)


def test_pinning_at_keeps_the_card_fixed_while_windows_stay_per_step(catalog):
    pricing = price_steps(
        [_step("peak", f"{MONDAY}T02:30:00+00:00"), _step("offpeak", f"{MONDAY}T12:00:00+00:00")],
        effective_at="2026-08-19",
        catalog=catalog,
    )
    assert {step.rate_card_id for step in pricing.steps} == {"deepseek:deepseek-v4-pro:2026-08-16"}
    assert [step.known_subtotal_usd for step in pricing.steps] == [5.28, 2.64]


def test_a_step_without_a_timestamp_is_not_priced_at_the_epoch(catalog):
    # Step.timestamp defaults to 0.0. Read as an instant that is 1970, which no
    # card covers -- the step would report `unknown` instead of a price.
    pricing = price_steps([_step("no-clock", None)], effective_at=MONDAY, catalog=catalog)
    assert pricing.steps[0].status == "complete"
    assert pricing.steps[0].known_subtotal_usd == 2.64  # base rates, no window


def test_price_run_on_a_recorded_run_uses_the_recorded_instants(catalog):
    run = Run(id="c" * 64, model_info="deepseek-v4-pro")
    for moment in (f"{MONDAY}T02:30:00+00:00", f"{MONDAY}T12:00:00+00:00"):
        run.add_step(
            StepKind.model,
            {"text": "ask"},
            {"text": "answer"},
            usage={"input": 1_000_000, "output": 1_000_000},
            provider="deepseek",
            model_info="deepseek-v4-pro",
        )
        object.__setattr__(run.steps[-1], "timestamp", datetime.fromisoformat(moment).timestamp())
    assert price_run(run, catalog=catalog).total_cost == pytest.approx(7.92)


# --------------------------------------------------------------------------- #
# the catalog: /2 bundled, /1 still loads
# --------------------------------------------------------------------------- #


def test_bundled_catalog_is_schema_2_and_verifies(catalog):
    raw = json.loads(BUNDLED_CATALOG.read_text(encoding="utf-8"))
    assert raw["schema"] == "opentine-pricing/2"
    assert raw["signature"]["key_id"] == "opentine-release-2026-07-r3"
    assert catalog.signed and catalog.id == f"sha256:{catalog.hash}"
    assert len(catalog.cards) == 85


@pytest.mark.parametrize("schema", ["opentine-pricing/1", "opentine-pricing/2"])
def test_both_catalog_schemas_load_and_price(tmp_path, schema):
    data = {
        "schema": schema,
        "cards": [
            {
                "id": "x:y:1",
                "provider": "x",
                "model": "y",
                "effective_from": "2026-01-01",
                "rates": {"input": "1", "output": "2"},
            }
        ],
    }
    data["catalog_id"] = f"sha256:{catalog_hash(data)}"
    path = tmp_path / f"{schema.replace('/', '-')}.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loaded = PricingCatalog.load(path, require_signature=False)
    result = bill("x", "y", MILLION, catalog=loaded, effective_at=f"{MONDAY}T02:30:00Z")
    assert result.amount_usd == Decimal("3")
    assert not loaded.cards[0].schedule


def test_a_schema_1_overlay_still_layers_over_the_bundled_catalog(tmp_path):
    # An overlay in the wild is written as /1 and carries no schedule; it must
    # keep winning over a bundled /2 card, schedule and all.
    data = {
        "schema": "opentine-pricing/1",
        "cards": [
            {
                "id": "deepseek:deepseek-v4-pro:house-rate",
                "provider": "deepseek",
                "model": "deepseek-v4-pro",
                "effective_from": "2026-01-01",
                "rates": {"input": "1", "output": "1"},
            }
        ],
    }
    data["catalog_id"] = f"sha256:{catalog_hash(data)}"
    overlay = tmp_path / "pricing.json"
    overlay.write_text(json.dumps(data), encoding="utf-8")
    merged = load_catalogs([BUNDLED_CATALOG, overlay])
    result = bill(
        "deepseek", "deepseek-v4-pro", MILLION, catalog=merged, effective_at=f"{MONDAY}T02:30:00Z"
    )
    assert result.rate_card_id == "deepseek:deepseek-v4-pro:house-rate"
    assert result.amount_usd == Decimal("2")


def test_an_unknown_catalog_schema_is_still_refused(tmp_path):
    data = {"schema": "opentine-pricing/3", "cards": []}
    data["catalog_id"] = f"sha256:{catalog_hash(data)}"
    path = tmp_path / "future.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(CatalogError, match="unsupported pricing catalog schema"):
        PricingCatalog.load(path, require_signature=False)


def test_a_scheduled_card_round_trips_through_the_catalog_json():
    card = _peak_card()
    restored = RateCard.from_dict(card.to_dict())
    assert restored == card
    assert card.to_dict()["schedule"] == [
        {
            "id": "peak",
            "days": "weekday",
            "hours": [{"start": "01:00", "end": "04:00"}, {"start": "06:00", "end": "10:00"}],
            "rates": {"input": "1.32", "output": "3.96"},
        }
    ]


def test_an_unscheduled_card_serializes_without_a_schedule_key():
    card = RateCard(id="a", provider="p", model="m", rates={"input": "1"})
    assert "schedule" not in card.to_dict()
    assert RateCard.from_dict(card.to_dict()) == card


# --------------------------------------------------------------------------- #
# malformed schedules are refused, not silently ignored
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "schedule",
    [
        {"id": "peak"},  # a mapping, not a list of windows
        ["peak"],
        [{"id": "peak", "hours": []}],
        [{"id": "peak", "hours": [{"start": "01:00", "end": "01:00"}]}],  # empty range
        [{"id": "peak", "hours": [{"start": "1:00", "end": "04:00"}]}],
        [{"id": "peak", "hours": [{"start": "25:00", "end": "26:00"}]}],
        [{"id": "peak", "hours": [{"start": "01:00"}]}],
        [{"id": "peak", "days": "holidays", "hours": [{"start": "01:00", "end": "04:00"}]}],
        [{"id": 3, "hours": [{"start": "01:00", "end": "04:00"}]}],
        [{"hours": [{"start": "01:00", "end": "04:00"}], "rates": {"": "1"}}],
        [{"hours": [{"start": "01:00", "end": "04:00"}], "rates": {"input": "-1"}}],
    ],
)
def test_a_malformed_schedule_is_refused(schedule):
    with pytest.raises(ValueError):
        RateCard(id="a", provider="p", model="m", rates={"input": "1"}, schedule=schedule)


def test_a_catalog_carrying_a_malformed_schedule_fails_to_load(tmp_path):
    data = {
        "schema": "opentine-pricing/2",
        "cards": [
            {
                "id": "x:y:1",
                "provider": "x",
                "model": "y",
                "effective_from": "2026-01-01",
                "rates": {"input": "1"},
                "schedule": [{"id": "peak", "hours": [{"start": "01:00", "end": "99:00"}]}],
            }
        ],
    }
    data["catalog_id"] = f"sha256:{catalog_hash(data)}"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(CatalogError, match="invalid pricing rate card"):
        PricingCatalog.load(path, require_signature=False)


# --------------------------------------------------------------------------- #
# 0.8.1: deepseek-v4-flash-vision-exp, carded at V4-Flash rates on its schedule
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("moment", "expected"),
    [
        # Off-peak: 0.22 in + 0.66 out on a 1M/1M call.
        (f"{MONDAY}T00:30:00Z", "0.88"),
        (f"{MONDAY}T12:00:00Z", "0.88"),
        # Peak (weekday 01:00-04:00 and 06:00-10:00 UTC): both rates double.
        (f"{MONDAY}T02:30:00Z", "1.76"),
        (f"{MONDAY}T07:00:00Z", "1.76"),
        # Beijing-time weekends are off-peak all day.
        (f"{SATURDAY}T02:30:00Z", "0.88"),
    ],
)
def test_flash_vision_exp_prices_exactly_like_flash_on_the_same_windows(catalog, moment, expected):
    vision = bill(
        "deepseek", "deepseek-v4-flash-vision-exp", MILLION, catalog=catalog, effective_at=moment
    )
    flash = bill("deepseek", "deepseek-v4-flash", MILLION, catalog=catalog, effective_at=moment)
    assert vision.status == "complete"
    assert vision.amount_usd == Decimal(expected)
    assert vision.amount_usd == flash.amount_usd
    assert vision.calculation["rates_per_million"] == flash.calculation["rates_per_million"]


def test_flash_vision_exp_is_priced_from_its_release_day_and_unknown_before_it():
    # Released 2026-08-21; peak still applied every day until the 2026-08-23
    # weekend rule, so the model's first Saturday keeps the all-days card.
    catalog = load_catalogs([BUNDLED_CATALOG])
    model = "deepseek-v4-flash-vision-exp"
    assert catalog.lookup("deepseek", model, effective_at="2026-08-20") is None
    assert bill("deepseek", model, MILLION, catalog=catalog, effective_at="2026-08-20").status == (
        "unknown"
    )
    first_day = catalog.lookup("deepseek", model, effective_at="2026-08-21")
    assert first_day is not None and first_day.schedule[0]["days"] == "all"
    saturday = bill(
        "deepseek", model, MILLION, catalog=catalog, effective_at="2026-08-22T02:30:00Z"
    )
    assert saturday.amount_usd == Decimal("1.76")  # all-days peak, before the weekend rule
    assert catalog.lookup("deepseek", model, effective_at="2026-08-23").schedule[0]["days"] == (
        "weekday"
    )


def test_flash_vision_exp_cache_reads_bill_at_the_flash_cache_rate(catalog):
    usage = Usage(input=0, cache_read=1_000_000, output=0)
    off_peak = bill(
        "deepseek",
        "deepseek-v4-flash-vision-exp",
        usage,
        catalog=catalog,
        effective_at=f"{MONDAY}T12:00:00Z",
    )
    peak = bill(
        "deepseek",
        "deepseek-v4-flash-vision-exp",
        usage,
        catalog=catalog,
        effective_at=f"{MONDAY}T02:30:00Z",
    )
    assert off_peak.amount_usd == Decimal("0.007")
    assert peak.amount_usd == Decimal("0.014")
