"""Validation for provider-reported identity and explicit rate overrides."""

from __future__ import annotations

from typing import Any

from opentine.billing import PricingCatalog, override_card


def model_name(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 512:
        return None
    return value


def validated_rates(
    provider: str, model: str, rates: dict[str, Any] | None
) -> dict[str, Any] | None:
    if rates is not None:
        override_card(provider, model, rates)
    return rates


def equivalent_model(
    catalog: PricingCatalog,
    provider: str,
    requested: str,
    reported: str | None,
    effective_at: Any,
) -> bool:
    """Recognize catalog aliases and Ollama's conventional ``:latest`` tag."""
    if reported is None or requested.casefold() == reported.casefold():
        return True
    if provider == "ollama" and f"{requested}:latest".casefold() == reported.casefold():
        return True
    requested_card = catalog.lookup(provider, requested, effective_at=effective_at)
    reported_card = catalog.lookup(provider, reported, effective_at=effective_at)
    return (
        requested_card is not None
        and reported_card is not None
        and requested_card.id == reported_card.id
    )
