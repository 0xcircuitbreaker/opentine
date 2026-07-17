"""Digest-covered billing metadata for normalized provider responses."""

from __future__ import annotations

from typing import Any

from opentine.billing import PricingCatalog, Usage, bill, known_cost
from opentine.models._provider_meta import model_name


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
    reported_model: Any = None,
) -> dict[str, Any]:
    raw_reported_model = reported_model
    reported_model = model_name(reported_model)
    invalid_reported_model = raw_reported_model is not None and reported_model is None
    priced_model = (
        "__invalid_reported_model__" if invalid_reported_model else reported_model or model
    )
    result = bill(
        provider,
        priced_model,
        usage,
        catalog=catalog,
        rate_override=rate_override if not invalid_reported_model or unmetered else None,
        service_tier=service_tier,
        unmetered=unmetered,
        effective_at=effective_at,
    )
    billing = result.to_dict()
    billing["calculation"].update(
        {"provider": provider, "requested_model": model, "reported_model": reported_model}
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
            components = billing["calculation"].get("components_usd") or {}
            billing["status"] = "partial" if components else "unknown"
            billing["amount_usd"] = None
        billing["warnings"].append(
            "provider usage omitted required dimensions: " + ", ".join(missing_usage)
        )
        billing["calculation"]["missing_usage_dimensions"] = list(missing_usage)
    return {
        "usage": usage.to_dict(),
        "billing": billing,
        "cost": 0.0
        if not usage_reported or (invalid_reported_model and billing["status"] != "unmetered")
        else known_cost(result),
    }
