"""Usage-completeness and model-aware Chat Completions billing."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from opentine.billing import PricingCatalog
from opentine.billing._context import billing_context
from opentine.models._metered import metered_response
from opentine.models._provider_meta import model_name
from opentine.models._usage import openai_missing_usage, openai_usage, value

_MAX_REPORTED_COST = Decimal("1e50")
_MISSING = object()
_USD_TICKS = 10_000_000_000


def _requires_cache_write(provider: str, requested: str, reported: Any) -> bool:
    actual = model_name(reported) or requested
    return provider == "openai" and actual.casefold().startswith("gpt-5.6")


def _reported_cost(value_: Any) -> Decimal | None:
    try:
        amount = Decimal(str(value_))
    except (InvalidOperation, OverflowError, TypeError, ValueError):
        return None
    return amount if amount.is_finite() and Decimal("0") <= amount <= _MAX_REPORTED_COST else None


def _openrouter_total(result: dict[str, Any], raw_usage: Any) -> dict[str, Any]:
    billing = result["billing"]
    calculation = billing["calculation"]
    calculation["candidate_rate_card_id"] = billing["rate_card_id"]
    calculation["candidate_components_usd"] = calculation.get("components_usd", {})
    billing["rate_card_id"] = None
    cost = _reported_cost(value(raw_usage, "cost"))
    if cost is None:
        billing.update(status="unknown", amount_usd=None, known_subtotal_usd="0")
        billing["warnings"].append("OpenRouter did not report a valid usage.cost; price is unknown")
        calculation.update(pricing_basis="provider_reported_total", components_usd={})
        result["cost"] = 0.0
        return result
    byok = value(raw_usage, "is_byok") is True
    upstream = _reported_cost(value(value(raw_usage, "cost_details"), "upstream_inference_cost"))
    with billing_context():
        total = cost + upstream if byok and upstream is not None else cost
    amount = str(total)
    billing.update(status="complete", amount_usd=amount, known_subtotal_usd=amount)
    billing["warnings"] = [
        warning
        for warning in billing["warnings"]
        if "price is unknown" not in warning and "cost is unknown" not in warning
    ]
    components = {"openrouter_account": str(cost)}
    if byok and upstream is not None:
        components["byok_upstream"] = str(upstream)
    calculation.update(
        pricing_basis="provider_reported_total",
        provider_reported_cost_usd=str(cost),
        is_byok=byok,
        components_usd=components,
    )
    if byok and upstream is None:
        billing.update(status="partial", amount_usd=None, known_subtotal_usd=str(cost))
        billing["warnings"].append(
            "OpenRouter BYOK upstream cost was not reported; only its account charge is known"
        )
        amount = str(cost)
    result["cost"] = float(Decimal(amount))
    return result


def _xai_total(result: dict[str, Any], raw_usage: Any) -> dict[str, Any]:
    raw_ticks = value(raw_usage, "cost_in_usd_ticks", _MISSING)
    if raw_ticks is _MISSING or raw_ticks is None:
        return result
    billing = result["billing"]
    calculation = billing["calculation"]
    calculation["candidate_rate_card_id"] = billing["rate_card_id"]
    calculation["candidate_components_usd"] = calculation.get("components_usd", {})
    billing["rate_card_id"] = None
    if type(raw_ticks) is not int or not 0 <= raw_ticks <= 10**60:
        billing.update(status="unknown", amount_usd=None, known_subtotal_usd="0")
        billing["warnings"].append("xAI reported invalid cost_in_usd_ticks; price is unknown")
        calculation.update(pricing_basis="provider_reported_total", components_usd={})
        result["cost"] = 0.0
        return result
    whole, fraction = divmod(raw_ticks, _USD_TICKS)
    amount = f"{whole}.{fraction:010d}".rstrip("0").rstrip(".")
    billing.update(status="complete", amount_usd=amount, known_subtotal_usd=amount)
    billing["warnings"] = [
        warning
        for warning in billing["warnings"]
        if "price is unknown" not in warning
        and "cost is unknown" not in warning
        and "Priority may fall back" not in warning
    ]
    calculation.update(
        pricing_basis="provider_reported_total",
        provider_reported_cost_ticks=str(raw_ticks),
        usd_ticks_per_dollar=_USD_TICKS,
        components_usd={"provider_reported_total": amount},
    )
    result["cost"] = float(Decimal(amount))
    return result


def chat_meter(
    provider: str,
    model: str,
    raw_usage: Any,
    catalog: PricingCatalog | None,
    rates: dict[str, Any] | None,
    service_tier: str | None,
    unmetered: bool,
    reported_model: Any,
    service_tier_observed: bool = True,
    requested_service_tier: str | None = None,
) -> dict[str, Any]:
    missing = openai_missing_usage(
        raw_usage,
        require_cache_write=_requires_cache_write(provider, model, reported_model),
    )
    result = metered_response(
        provider,
        model,
        openai_usage(raw_usage, additive_reasoning=provider == "xai"),
        catalog=catalog,
        rate_override=rates,
        service_tier=service_tier,
        unmetered=unmetered,
        usage_reported=raw_usage is not None,
        missing_usage=missing,
        partitioned_usage_incomplete="cache_write_5m" in missing,
        reported_model=reported_model,
        requested_service_tier=requested_service_tier,
        service_tier_observed=service_tier_observed,
    )
    if provider == "openrouter" and rates is None and not unmetered:
        return _openrouter_total(result, raw_usage)
    if provider == "xai" and rates is None and not unmetered:
        return _xai_total(result, raw_usage)
    return result
