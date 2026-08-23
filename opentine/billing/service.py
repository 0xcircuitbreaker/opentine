"""High-level resolution order used by provider adapters."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date, datetime
from pathlib import Path
from typing import Any

from opentine.billing.catalog import PricingCatalog, load_catalogs
from opentine.billing.engine import calculate
from opentine.billing.types import BillingResult, RateCard, Usage, billing_moment, decimal


def override_card(
    provider: str,
    model: str,
    rates: dict[str, Any],
    *,
    unmetered: bool = False,
) -> RateCard:
    return RateCard(
        id=f"override:{provider}:{model}",
        provider=provider,
        model=model,
        rates={name: decimal(value) for name, value in rates.items()},
        effective_from=date.min,
        unmetered=unmetered,
        metadata={"override": True},
    )


def bill(
    provider: str,
    model: str,
    usage: Usage | dict[str, Any],
    *,
    effective_at: date | datetime | str | None = None,
    billed_at: date | datetime | str | None = None,
    service_tier: str | None = None,
    rate_override: dict[str, Any] | None = None,
    unmetered: bool = False,
    catalog: PricingCatalog | None = None,
    catalog_paths: Iterable[str | Path] | None = None,
) -> BillingResult:
    """Price usage against the catalog card effective at ``effective_at``.

    ``effective_at`` may carry a time of day: its *date* selects the rate card,
    its *time* selects that card's time-of-day window when it has a schedule. A
    plain date selects the card and prices from base rates. ``billed_at`` splits
    the two, for callers that pin the card date but keep a recorded instant.
    """
    normalized = usage if isinstance(usage, Usage) else Usage.from_dict(usage)
    selected = catalog or load_catalogs(catalog_paths)
    when, moment = billing_moment(effective_at)
    card = (
        override_card(provider, model, rate_override or {}, unmetered=unmetered)
        if rate_override is not None or unmetered
        else selected.lookup(provider, model, effective_at=when, service_tier=service_tier)
    )
    return calculate(
        normalized,
        card,
        catalog_id=selected.id,
        catalog_hash=selected.hash,
        effective_at=moment if moment is not None else when,
        billed_at=billed_at,
        service_tier=service_tier,
        catalog_provenance=selected.provenance,
    )


def known_cost(result: BillingResult) -> float:
    return float(result.known_subtotal_usd)
