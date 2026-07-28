"""Explicit local-infrastructure rate overrides for Ollama."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from opentine.billing._context import billing_context
from opentine.models._provider_meta import validated_rates


def rate_override(
    input_per_mtok: float | None,
    output_per_mtok: float | None,
    compute_per_second: float | None,
) -> dict[str, Any] | None:
    if input_per_mtok is output_per_mtok is compute_per_second is None:
        return None
    token_mode = input_per_mtok is not None or output_per_mtok is not None
    if token_mode and compute_per_second is not None:
        raise ValueError("Ollama token rates and compute rates are mutually exclusive")
    rates: dict[str, Any] = {}
    if input_per_mtok is not None:
        rates["input"] = input_per_mtok
    if output_per_mtok is not None:
        rates["output"] = output_per_mtok
    if token_mode:
        rates.update(
            {
                name: 0
                for name in (
                    "total_seconds",
                    "load_seconds",
                    "prompt_eval_seconds",
                    "eval_seconds",
                )
            }
        )
    if compute_per_second is not None:
        with billing_context():
            per_second = Decimal(str(compute_per_second)) * 1_000_000
        rates.update(
            {
                "input": 0,
                "output": 0,
                "prompt_eval_seconds": per_second,
                "eval_seconds": per_second,
                "total_seconds": 0,
                "load_seconds": 0,
            }
        )
    return validated_rates("ollama", "local", rates)
