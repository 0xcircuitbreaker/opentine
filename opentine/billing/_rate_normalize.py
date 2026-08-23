"""Defensive normalization for immutable rate-card containers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opentine.billing._immutable import freeze
from opentine.billing._schedule import normalize_schedule
from opentine.billing._values import decimal


def normalize_rate_card(card: Any) -> None:
    mappings = (card.rates, card.service_modifiers, card.service_rates, card.metadata)
    if any(not isinstance(value, Mapping) for value in mappings):
        raise ValueError("rate-card rate, modifier, and metadata fields must be objects")
    if not isinstance(card.context_thresholds, (tuple, list)):
        raise ValueError("rate-card context thresholds must be a list")
    object.__setattr__(card, "aliases", tuple(card.aliases))
    object.__setattr__(card, "source_urls", tuple(card.source_urls))
    object.__setattr__(
        card, "rates", freeze({key: decimal(value) for key, value in card.rates.items()})
    )
    thresholds = []
    for raw in card.context_thresholds:
        if not isinstance(raw, Mapping):
            raise ValueError("rate-card context threshold is malformed")
        rule = dict(raw)
        multipliers = rule.get("multipliers")
        if isinstance(multipliers, Mapping):
            rule["multipliers"] = {key: decimal(value) for key, value in multipliers.items()}
        thresholds.append(freeze(rule))
    object.__setattr__(card, "context_thresholds", tuple(thresholds))
    modifiers = {
        key: freeze({name: decimal(rate) for name, rate in value.items()})
        if isinstance(value, Mapping)
        else decimal(value)
        for key, value in card.service_modifiers.items()
    }
    object.__setattr__(card, "service_modifiers", freeze(modifiers))
    rates = {}
    for tier, values in card.service_rates.items():
        if not isinstance(values, Mapping):
            raise ValueError("rate-card service rates must contain objects")
        rates[tier] = {name: decimal(rate) for name, rate in values.items()}
    object.__setattr__(card, "service_rates", freeze(rates))
    object.__setattr__(card, "schedule", normalize_schedule(card.schedule))
    object.__setattr__(card, "currency_to_usd", decimal(card.currency_to_usd))
    object.__setattr__(card, "metadata", freeze(card.metadata))
