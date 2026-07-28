"""Ollama timing normalization and local-infrastructure billing."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from opentine.billing import PricingCatalog
from opentine.billing._context import billing_context
from opentine.models._metered import metered_response
from opentine.models._usage import missing_usage_dimensions, ollama_usage


def ollama_meter(
    model: str,
    data: dict[str, Any],
    catalog: PricingCatalog | None,
    rates: dict[str, Any] | None,
    compute_rate: bool,
) -> dict[str, Any]:
    normalized = dict(data)
    with billing_context():
        for source, target in (
            ("total_duration", "total_seconds"),
            ("load_duration", "load_seconds"),
            ("prompt_eval_duration", "prompt_eval_seconds"),
            ("eval_duration", "eval_seconds"),
        ):
            if source in normalized:
                normalized[target] = Decimal(normalized[source]) / Decimal(1_000_000_000)
                normalized.pop(source)
    required = (
        {
            "prompt_eval_seconds": ("prompt_eval_duration",),
            "eval_seconds": ("eval_duration",),
        }
        if compute_rate
        else {"input": ("prompt_eval_count",), "output": ("eval_count",)}
    )
    usage_fields = (
        ("prompt_eval_duration", "eval_duration")
        if compute_rate
        else ("prompt_eval_count", "eval_count")
    )
    return metered_response(
        "ollama",
        model,
        ollama_usage(normalized),
        catalog=catalog,
        rate_override=rates,
        unmetered=rates is None,
        usage_reported=any(name in data for name in usage_fields),
        missing_usage=missing_usage_dimensions(data, required),
        reported_model=data.get("model"),
    )
