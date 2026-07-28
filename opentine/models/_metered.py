"""Digest-covered billing metadata for normalized provider responses."""

from __future__ import annotations

from typing import Any

from opentine.billing import PricingCatalog, Usage, bill, known_cost, load_catalogs
from opentine.billing.types import as_date
from opentine.models._provider_meta import equivalent_model, model_name


def metered_response(
    provider: str,
    model: str,
    usage: Usage,
    *,
    catalog: PricingCatalog | None = None,
    rate_override: dict[str, Any] | None = None,
    service_tier: str | None = None,
    unmetered: bool = False,
    effective_at: str | None = None,
    usage_reported: bool = True,
    missing_usage: tuple[str, ...] = (),
    partitioned_usage_incomplete: bool = False,
    reported_model: Any = None,
    requested_service_tier: str | None = None,
    service_tier_observed: bool = True,
) -> dict[str, Any]:
    raw_reported_model = reported_model
    reported_model = model_name(reported_model)
    invalid_reported_model = raw_reported_model is not None and reported_model is None
    priced_model = (
        "__invalid_reported_model__" if invalid_reported_model else reported_model or model
    )
    selected = catalog or load_catalogs()
    when = as_date(effective_at)
    same_model = not invalid_reported_model and equivalent_model(
        selected, provider, model, reported_model, when
    )
    result = bill(
        provider,
        priced_model,
        usage,
        catalog=selected,
        rate_override=(rate_override if unmetered or same_model else None),
        service_tier=service_tier,
        unmetered=unmetered,
        effective_at=when,
    )
    billing = result.to_dict()
    compatibility_cost = known_cost(result)
    billing["calculation"].update(
        {"provider": provider, "requested_model": model, "reported_model": reported_model}
    )
    if requested_service_tier not in (None, ""):
        billing["calculation"].update(
            requested_service_tier=requested_service_tier,
            service_tier_observed=service_tier_observed,
        )
    if invalid_reported_model:
        billing["warnings"].append(
            "provider reported an invalid model identifier; price is unknown"
        )
        billing["calculation"]["invalid_reported_model_type"] = type(raw_reported_model).__name__
        if billing["status"] != "unmetered":
            billing.update(status="unknown", amount_usd=None, known_subtotal_usd="0")
    if reported_model and reported_model.casefold() != model.casefold():
        billing["warnings"].append(
            f"provider reported model {reported_model!r} for requested model {model!r}"
        )
        if rate_override is not None and not unmetered and not same_model:
            billing["warnings"].append("explicit rates were ignored for the different model")
    if not usage_reported:
        if billing["status"] != "unmetered":
            billing.update(status="unknown", amount_usd=None, known_subtotal_usd="0")
        warning = (
            "provider did not report usage; API cost remains unmetered"
            if billing["status"] == "unmetered"
            else "provider did not report usage; cost is unknown"
        )
        billing["warnings"].append(warning)
        billing["calculation"]["usage_reported"] = False
    elif missing_usage:
        if billing["status"] != "unmetered":
            calculation = billing["calculation"]
            components = calculation.get("components_usd") or {}
            if partitioned_usage_incomplete:
                calculation["candidate_components_usd"] = components
                calculation["candidate_known_subtotal_usd"] = billing["known_subtotal_usd"]
                calculation["components_usd"] = {}
                billing.update(status="unknown", amount_usd=None, known_subtotal_usd="0")
                compatibility_cost = 0.0
            else:
                billing["status"] = "partial" if components else "unknown"
                billing["amount_usd"] = None
        billing["warnings"].append(
            "provider usage omitted required dimensions: " + ", ".join(missing_usage)
        )
        billing["calculation"]["missing_usage_dimensions"] = list(missing_usage)
        if partitioned_usage_incomplete and billing["status"] != "unmetered":
            billing["warnings"].append(
                "missing usage makes token partitions indeterminate; "
                "candidate charges are not a known subtotal"
            )
    uncertain_priority = (
        provider in {"openai", "xai"}
        and str(requested_service_tier).casefold() == "priority"
        and not service_tier_observed
        and rate_override is None
        and not unmetered
    )
    if uncertain_priority:
        calculation = billing["calculation"]
        calculation.setdefault("candidate_components_usd", calculation.get("components_usd", {}))
        calculation.setdefault("candidate_known_subtotal_usd", billing["known_subtotal_usd"])
        calculation["components_usd"] = {}
        calculation["requested_service_tier"] = "priority"
        calculation["service_tier_observed"] = False
        billing.update(status="unknown", amount_usd=None, known_subtotal_usd="0")
        billing["warnings"].append(
            f"{provider} Priority may fall back; response tier was not observed"
        )
        compatibility_cost = 0.0
    return {
        "usage": usage.to_dict(),
        "billing": billing,
        "cost": 0.0
        if not usage_reported or (invalid_reported_model and billing["status"] != "unmetered")
        else compatibility_cost,
    }
