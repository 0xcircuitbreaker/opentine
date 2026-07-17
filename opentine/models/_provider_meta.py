"""Validation for provider-reported identity and explicit rate overrides."""

from __future__ import annotations

from typing import Any

from opentine.billing import override_card


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
