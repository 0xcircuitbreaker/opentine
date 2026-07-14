"""Decimal billing arithmetic and deterministic card resolution."""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from opentine.billing.types import BillingResult, RateCard, Usage, as_date, decimal

_MILLION = Decimal(1_000_000)


def _threshold_rates(card: RateCard, usage: Usage) -> tuple[dict[str, Decimal], list[str]]:
    rates = dict(card.rates)
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

    rates, threshold_rules = _threshold_rates(card, usage)
    requested_tier = service_tier or "standard"
    modifier = card.service_modifiers.get(requested_tier, Decimal("1"))
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
        amount = count * rate / _MILLION * modifier * card.currency_to_usd
        known += amount
        components[dimension] = str(amount)

    warnings: list[str] = []
    if requested_tier != "standard" and requested_tier not in card.service_modifiers:
        missing.append(f"service_tier:{requested_tier}")
        warnings.append(f"rate card has no modifier for service tier {requested_tier!r}")
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
            "service_modifier": str(modifier),
            "currency": card.currency,
            "currency_to_usd": str(card.currency_to_usd),
        }
    )
    positive = any(decimal(value) > 0 for value in usage.dimensions().values())
    if missing and components:
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
