"""High-level resolution order used by provider adapters."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from opentine.billing.catalog import PricingCatalog, load_catalogs
from opentine.billing.engine import calculate
from opentine.billing.types import BillingResult, RateCard, Usage, decimal


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
    service_tier: str | None = None,
    rate_override: dict[str, Any] | None = None,
    unmetered: bool = False,
    catalog: PricingCatalog | None = None,
    catalog_paths: Iterable[str | Path] | None = None,
) -> BillingResult:
    normalized = usage if isinstance(usage, Usage) else Usage.from_dict(usage)
    selected = catalog or load_catalogs(catalog_paths)
    card = (
        override_card(provider, model, rate_override or {}, unmetered=unmetered)
        if rate_override is not None or unmetered
        else selected.lookup(provider, model, effective_at=effective_at, service_tier=service_tier)
    )
    return calculate(
        normalized,
        card,
        catalog_id=selected.id,
        catalog_hash=selected.hash,
        effective_at=effective_at,
        service_tier=service_tier,
        catalog_provenance=selected.provenance,
    )


def known_cost(result: BillingResult) -> float:
    return float(result.known_subtotal_usd.quantize(Decimal("0.000000000001")))
