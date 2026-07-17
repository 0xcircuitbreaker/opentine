"""Current Anthropic sampling, thinking, and billing wire rules."""

from __future__ import annotations

from typing import Any

from opentine.models._usage import value


def validate_service_tier(tier: str | None) -> None:
    if tier not in (None, "auto", "standard_only"):
        raise ValueError("Anthropic Messages service_tier must be 'auto' or 'standard_only'")


def model_rules(model: str) -> tuple[bool, bool, bool]:
    name = model.lower().replace(".", "-")
    supports = any(item in name for item in ("opus", "sonnet", "fable", "mythos"))
    explicit_adaptive = any(
        item in name for item in ("opus-4-6", "opus-4-7", "opus-4-8", "sonnet-4-6")
    )
    restricted_sampling = explicit_adaptive or any(
        item in name for item in ("fable-5", "mythos-5", "mythos-preview", "sonnet-5")
    )
    return supports, restricted_sampling, explicit_adaptive


def pricing_tier(
    response: Any, configured_tier: str | None, configured_geo: str | None
) -> str | None:
    usage = value(response, "usage")
    tier = value(usage, "service_tier") or value(response, "service_tier") or configured_tier
    geo = value(usage, "inference_geo") or configured_geo
    if geo != "us":
        return tier
    if tier in (None, "", "default", "standard", "standard_only"):
        return "us"
    return f"{tier}_us"
