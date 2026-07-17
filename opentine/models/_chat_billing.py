"""Usage-completeness and model-aware Chat Completions billing."""

from __future__ import annotations

from typing import Any

from opentine.billing import PricingCatalog
from opentine.models._metered import metered_response
from opentine.models._usage import missing_usage_dimensions, openai_usage


def chat_meter(
    provider: str,
    model: str,
    raw_usage: Any,
    catalog: PricingCatalog | None,
    rates: dict[str, Any] | None,
    service_tier: str | None,
    unmetered: bool,
    reported_model: Any,
) -> dict[str, Any]:
    return metered_response(
        provider,
        model,
        openai_usage(raw_usage),
        catalog=catalog,
        rate_override=rates,
        service_tier=service_tier,
        unmetered=unmetered,
        usage_reported=raw_usage is not None,
        missing_usage=missing_usage_dimensions(
            raw_usage,
            {
                "input": ("input_tokens", "prompt_tokens"),
                "output": ("output_tokens", "completion_tokens"),
            },
        ),
        reported_model=reported_model,
    )
