"""Current Anthropic sampling, thinking, and billing wire rules."""

from __future__ import annotations

from typing import Any

from opentine.models._usage import value


def validate_service_tier(tier: str | None) -> None:
    if tier not in (None, "auto", "standard_only"):
        raise ValueError("Anthropic Messages service_tier must be 'auto' or 'standard_only'")


#: Early-refusal categories Anthropic bills (since 2026-09-24, on every platform):
#: "a refusal that arrives before any output is billed when its
#: ``stop_details.category`` is ``"bio"``, ``"frontier_llm"``, or
#: ``"reasoning_extraction"`` ... A refusal before any output in any other
#: category, or with a ``null`` category, is not billed."
BILLED_EARLY_REFUSAL_CATEGORIES = frozenset({"bio", "frontier_llm", "reasoning_extraction"})


def model_rules(model: str) -> tuple[bool, bool, bool]:
    name = model.lower().replace(".", "-")
    # Haiku 4.5 rejects adaptive thinking; the Haiku 5 line has it.
    supports = any(item in name for item in ("opus", "sonnet", "fable", "mythos", "haiku-5"))
    explicit_adaptive = any(
        item in name for item in ("opus-4-6", "opus-4-7", "opus-4-8", "sonnet-4-6")
    )
    # Models on which "non-default temperature, top_p, or top_k values return a
    # 400 error on every request": Fable 5/5.1, Mythos 5/5.1/Preview, Opus 5/5.5,
    # Opus 4.7/4.8, Sonnet 5/5.5, Haiku 5.5. "opus-5" also matches opus-5-5.
    restricted_sampling = explicit_adaptive or any(
        item in name
        for item in ("fable-5", "mythos-5", "mythos-preview", "sonnet-5", "opus-5", "haiku-5")
    )
    return supports, restricted_sampling, explicit_adaptive


def refusal_category(response: Any) -> str | None:
    """The refusal's ``stop_details.category``, bounded for the digest-covered record."""
    category = value(value(response, "stop_details"), "category")
    if category is None:
        return None
    if not isinstance(category, str) or not category or len(category) > 128:
        return "invalid"
    return category


def early_refusal_is_free(category: str | None) -> bool:
    # A malformed category is not evidence of a free refusal, so it stays billed.
    return category != "invalid" and category not in BILLED_EARLY_REFUSAL_CATEGORIES


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
