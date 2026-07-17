"""Decimal billing arithmetic and deterministic card resolution."""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from opentine.billing.types import BillingResult, RateCard, Usage, as_date, decimal

_MILLION = Decimal(1_000_000)


def _threshold_rates(
    card: RateCard, usage: Usage, rates: dict[str, Decimal] | None = None
) -> tuple[dict[str, Decimal], list[str]]:
    rates = dict(rates or card.rates)
    matching = [
        rule
        for rule in card.context_thresholds
        if usage.input_total > int(rule.get("input_tokens", 0))
    ]
    if not matching:
        return rates, []
    # Tiered context pricing: only the highest matching tier applies. Its multipliers
    # replace the base rates rather than compounding across every crossed threshold.
    rule = max(matching, key=lambda item: int(item.get("input_tokens", 0)))
    threshold = int(rule.get("input_tokens", 0))
    for dimension, multiplier in (rule.get("multipliers") or {}).items():
        if dimension in rates:
            rates[dimension] *= decimal(multiplier, "1")
    return rates, [str(rule.get("id") or f"input>{threshold}")]


def calculate(
    usage: Usage,
    card: RateCard | None,
    *,
    catalog_id: str | None = None,
    catalog_hash: str | None = None,
    effective_at: date | datetime | str | None = None,
    service_tier: str | None = None,
    catalog_provenance: tuple[dict[str, Any], ...] = (),
) -> BillingResult:
    when = as_date(effective_at)
    iso_when = when.isoformat()
    calculation: dict[str, Any] = {
        "usage": usage.to_dict(compact=False),
        "service_tier": service_tier or "standard",
    }
    if card is None:
        return BillingResult(
            "unknown",
            None,
            Decimal("0"),
            catalog_id,
            catalog_hash,
            effective_at=iso_when,
            warnings=("no exact provider/model rate card; price is unknown",),
            calculation=calculation,
            catalog_provenance=catalog_provenance,
        )
    if card.unmetered:
        calculation["currency"] = card.currency
        return BillingResult(
            "unmetered",
            Decimal("0"),
            Decimal("0"),
            catalog_id,
            catalog_hash,
            card.id,
            iso_when,
            ("API usage is unmetered; local infrastructure cost may still apply",),
            calculation,
            catalog_provenance,
        )

    reported_tier = str(service_tier) if service_tier not in (None, "") else "standard"
    requested_tier = (
        "standard" if reported_tier in {"default", "standard", "standard_only"} else reported_tier
    )
    calculation["service_tier"] = reported_tier
    if requested_tier != reported_tier:
        calculation["normalized_service_tier"] = requested_tier
    known_tiers = card.service_modifiers.keys() | card.service_rates.keys()
    if (
        requested_tier != "standard"
        and requested_tier not in known_tiers
        and not card.metadata.get("override")
    ):
        return BillingResult(
            "unknown",
            None,
            Decimal("0"),
            catalog_id,
            catalog_hash,
            card.id,
            iso_when,
            (f"rate card has no pricing for service tier {reported_tier!r}",),
            calculation,
            catalog_provenance,
        )
    rates = dict(card.rates)
    service_rates = card.service_rates.get(requested_tier, {})
    rates.update(service_rates)
    rates, threshold_rules = _threshold_rates(card, usage, rates)
    raw_modifier = card.service_modifiers.get(requested_tier, Decimal("1"))
    dimensional_modifier = isinstance(raw_modifier, dict)
    dimension_modifiers = raw_modifier if dimensional_modifier else {}
    known = Decimal("0")
    missing: list[str] = []
    components: dict[str, str] = {}
    for dimension, raw_count in usage.dimensions().items():
        count = decimal(raw_count)
        if not count:
            continue
        rate = rates.get(dimension)
        if rate is None:
            missing.append(dimension)
            continue
        modifier = (
            decimal(dimension_modifiers.get(dimension), "1")
            if dimensional_modifier
            else decimal(raw_modifier, "1")
        )
        amount = count * rate / _MILLION * modifier * card.currency_to_usd
        known += amount
        components[dimension] = str(amount)

    warnings: list[str] = []
    if not rates:
        warnings.append("rate card has no applicable rates; price is unknown")
    if missing:
        warnings.append("missing rates for usage dimensions: " + ", ".join(sorted(missing)))
    if card.currency != "USD":
        warnings.append(
            f"converted {card.currency} to USD using pinned factor {card.currency_to_usd}"
        )
    calculation.update(
        {
            "rates_per_million": {key: str(value) for key, value in sorted(rates.items())},
            "components_usd": components,
            "context_rules": threshold_rules,
            "service_modifier": {
                key: str(value) for key, value in sorted(dimension_modifiers.items())
            }
            if dimensional_modifier
            else str(raw_modifier),
            "service_rates_per_million": {
                key: str(value) for key, value in sorted(service_rates.items())
            },
            "currency": card.currency,
            "currency_to_usd": str(card.currency_to_usd),
        }
    )
    positive = any(decimal(value) > 0 for value in usage.dimensions().values())
    if not rates:
        status = "unknown"
    elif missing and components:
        status = "partial"
    elif missing or (positive and not components):
        status = "unknown"
    else:
        status = "complete"
    amount = known if status == "complete" else None
    return BillingResult(
        status,
        amount,
        known,
        catalog_id,
        catalog_hash,
        card.id,
        iso_when,
        tuple(warnings),
        calculation,
        catalog_provenance,
    )


def now_utc() -> datetime:
    return datetime.now(UTC)
