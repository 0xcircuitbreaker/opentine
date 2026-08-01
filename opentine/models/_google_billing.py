"""Google usage completeness and model-aware catalog billing."""

from __future__ import annotations

from typing import Any

from opentine.billing import PricingCatalog
from opentine.models._metered import metered_response
from opentine.models._usage import google_usage, missing_usage_dimensions, value


def _tier(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).lower().rsplit(".", 1)[-1].replace("-", "_")
    aliases = {
        "default": "standard",
        "on_demand": "standard",
        "on_demand_flex": "flex",
        "on_demand_priority": "priority",
    }
    return aliases.get(normalized, normalized)


def google_header_tier(response: Any) -> str | None:
    sdk_response = value(response, "sdk_http_response") or value(response, "sdkHttpResponse")
    headers = value(sdk_response, "headers", {}) or {}
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return None
    return _tier(getter("x-gemini-service-tier") or getter("X-Gemini-Service-Tier"))


def google_service_tier(
    raw_usage: Any, configured: str | None, response_tier: str | None = None
) -> str | None:
    reported = response_tier or (
        value(raw_usage, "service_tier")
        or value(raw_usage, "serviceTier")
        or value(raw_usage, "traffic_type")
        or value(raw_usage, "trafficType")
    )
    return _tier(reported) or configured


def google_meter(
    model: str,
    raw_usage: Any,
    catalog: PricingCatalog | None,
    rates: dict[str, Any] | None,
    service_tier: str | None,
    reported_model: str | None,
    *,
    provider: str = "google",
) -> dict[str, Any]:
    return metered_response(
        provider,
        model,
        google_usage(raw_usage),
        catalog=catalog,
        rate_override=rates,
        service_tier=service_tier,
        usage_reported=raw_usage is not None,
        missing_usage=missing_usage_dimensions(
            raw_usage,
            {
                "input": ("prompt_token_count", "promptTokenCount"),
                "output": ("candidates_token_count", "candidatesTokenCount"),
            },
        ),
        reported_model=reported_model,
    )
