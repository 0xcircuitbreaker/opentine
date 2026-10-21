"""JSON form of a rate card (split from ``types`` for the module size gate)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opentine.billing._immutable import thaw
from opentine.billing._schedule import schedule_to_json


def card_to_dict(card: Any) -> dict[str, Any]:
    # ``schedule`` is emitted only when the card has one, so every existing
    # (unscheduled) card serializes byte-identically to what /1 produced.
    scheduled = {"schedule": schedule_to_json(card.schedule)} if card.schedule else {}
    # Likewise the /3 media fields: a card without them is unchanged.
    media = {
        name: dict(sorted(getattr(card, name).items()))
        for name in ("units", "same_rate_as")
        if getattr(card, name)
    }
    return {
        **scheduled,
        **media,
        "id": card.id,
        "provider": card.provider,
        "model": card.model,
        "aliases": list(card.aliases),
        "effective_from": card.effective_from.isoformat(),
        "effective_until": card.effective_until.isoformat() if card.effective_until else None,
        "rates": {key: str(value) for key, value in sorted(card.rates.items())},
        "context_thresholds": [
            {
                **thaw(rule),
                "multipliers": {
                    key: str(value) for key, value in (rule.get("multipliers") or {}).items()
                },
            }
            for rule in card.context_thresholds
        ],
        "service_modifiers": {
            key: {name: str(rate) for name, rate in sorted(value.items())}
            if isinstance(value, Mapping)
            else str(value)
            for key, value in sorted(card.service_modifiers.items())
        },
        "service_rates": {
            tier: {name: str(rate) for name, rate in sorted(rates.items())}
            for tier, rates in sorted(card.service_rates.items())
        },
        "currency": card.currency,
        "currency_to_usd": str(card.currency_to_usd),
        "source_urls": list(card.source_urls),
        "verified_at": card.verified_at.isoformat() if card.verified_at else None,
        "unmetered": card.unmetered,
        "metadata": thaw(card.metadata),
    }
