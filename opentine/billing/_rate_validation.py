"""Structural validation for public pricing rate-card records."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from decimal import Decimal
from typing import Any


def validate_rate_card_data(data: Any) -> None:
    if not isinstance(data, dict):
        raise ValueError("rate card must be an object")
    for field in ("rates", "service_modifiers", "service_rates", "metadata"):
        if field in data and not isinstance(data[field], dict):
            raise ValueError(f"rate-card {field} must be an object")
    for field in ("aliases", "context_thresholds", "schedule", "source_urls"):
        if field in data and not isinstance(data[field], list):
            raise ValueError(f"rate-card {field} must be a list")
    for field in ("effective_from", "effective_until", "verified_at"):
        if field in data and data[field] is not None and not isinstance(data[field], str):
            raise ValueError(f"rate-card {field} must be an ISO date string")
    if "unmetered" in data and type(data["unmetered"]) is not bool:
        raise ValueError("rate-card unmetered must be a boolean")


def validate_rate_card(card: Any) -> None:
    for field in ("id", "provider", "model", "currency"):
        value = getattr(card, field)
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise ValueError(f"rate-card {field} must be a non-empty bounded string")
    if not isinstance(card.aliases, (tuple, list)) or not all(
        isinstance(value, str) and value for value in card.aliases
    ):
        raise ValueError("rate-card aliases must contain non-empty strings")
    if type(card.effective_from) is not date or (
        card.effective_until is not None and type(card.effective_until) is not date
    ):
        raise ValueError("rate-card effective dates must be dates")
    if card.effective_until is not None and card.effective_until < card.effective_from:
        raise ValueError("rate-card effective date range is inverted")
    mappings = (card.rates, card.service_modifiers, card.service_rates, card.metadata)
    if any(not isinstance(value, Mapping) for value in mappings):
        raise ValueError("rate-card rate, modifier, and metadata fields must be objects")
    if any(not isinstance(name, str) or not name for name in card.rates):
        raise ValueError("rate-card dimensions must be non-empty strings")
    if not isinstance(card.context_thresholds, (tuple, list)):
        raise ValueError("rate-card context thresholds must be a list")
    for rule in card.context_thresholds:
        threshold = rule.get("input_tokens") if isinstance(rule, Mapping) else None
        multipliers = rule.get("multipliers", {}) if isinstance(rule, Mapping) else None
        if type(threshold) is not int or threshold < 0 or not isinstance(multipliers, Mapping):
            raise ValueError("rate-card context threshold is malformed")
    for group in card.service_rates.values():
        if not isinstance(group, Mapping) or any(
            not isinstance(name, str) or not name for name in group
        ):
            raise ValueError("rate-card service rates must contain objects")
    for modifier in card.service_modifiers.values():
        if not isinstance(modifier, (Mapping, int, float, Decimal)) or isinstance(modifier, bool):
            raise ValueError("rate-card service modifier is malformed")
    if not isinstance(card.source_urls, (tuple, list)) or not all(
        isinstance(value, str) for value in card.source_urls
    ):
        raise ValueError("rate-card source URLs must contain strings")
    if type(card.unmetered) is not bool:
        raise ValueError("rate-card unmetered must be a boolean")
