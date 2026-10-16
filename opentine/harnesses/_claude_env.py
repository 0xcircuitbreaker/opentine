"""What a Claude Code session's environment and usage say about who billed it.

Split out of :mod:`opentine.harnesses._claude_stream` for the module line cap.

* **Provider.** Bedrock, Vertex and Foundry are switched on by environment flags.
  ``ANTHROPIC_BASE_URL`` pointed at anything but Anthropic (Ollama, LM Studio,
  llama.cpp, a gateway) still reported ``firstParty`` and was recorded as
  ``anthropic``, so ``tine price`` billed Claude list prices for local tokens. A
  loopback base URL now records :data:`LOCAL_PROVIDER` (unmetered); any other
  non-Anthropic host records :data:`COMPATIBLE_PROVIDER`, which no card prices.
* **Service tier.** ``usage.speed == "fast"`` is fast mode (2x on the cards);
  ``inference_geo == "us"`` is US-only inference. Both were ignored, so fast
  runs re-priced at 1x.
* **Reported cost.** ``modelUsage[*].costBasis`` says whether Claude Code's own
  ``total_cost_usd`` is a list-price figure; for anything else (``managed``,
  ``unknown`` -- e.g. a local model under a Claude alias) it is an estimate and is
  recorded as one, not booked as the run's cost.
* **Trace context.** ``claude -p`` joins an inbound W3C ``TRACEPARENT``, so a
  harness run that sets one can be matched with Claude Code's own OTel trace.
"""

from __future__ import annotations

import ipaddress
import secrets
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from opentine.harnesses._types import MAX_COUNT, bounded_number

LOCAL_PROVIDER = "local-anthropic-compatible"
COMPATIBLE_PROVIDER = "anthropic-compatible"
_ENV_PROVIDERS = (
    ("CLAUDE_CODE_USE_BEDROCK", "bedrock"),
    ("CLAUDE_CODE_USE_VERTEX", "vertex"),
    ("CLAUDE_CODE_USE_FOUNDRY", "foundry"),
)


def _count(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= MAX_COUNT else None


def _money(value: Any) -> float:
    # A malformed figure from the CLI must not abort the run it describes, nor a
    # JSON integer too large for a float (final pass 5, #10).
    if not isinstance(value, int | float):
        return 0.0
    return bounded_number(value) or 0.0


def _on(value: Any) -> bool:
    return str(value or "").strip().casefold() not in ("", "0", "false")


def _loopback(host: str) -> bool:
    if host.rstrip(".").casefold() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    return address.is_loopback or bool(mapped and mapped.is_loopback)


def base_url_provider(url: Any) -> str | None:
    """The provider a non-Anthropic ``ANTHROPIC_BASE_URL`` stands for, or ``None``."""
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        host = (urlsplit(url.strip()).hostname or "").casefold()
    except ValueError:
        return COMPATIBLE_PROVIDER
    if host == "anthropic.com" or host.endswith(".anthropic.com"):
        return None
    return LOCAL_PROVIDER if _loopback(host) else COMPATIBLE_PROVIDER


def env_provider(env: Mapping[str, str]) -> tuple[str, bool]:
    """``(provider, overridden)``: who serves the session, and whether a base URL decided it."""
    for name, provider in _ENV_PROVIDERS:
        if _on(env.get(name)):
            return provider, False
    override = base_url_provider(env.get("ANTHROPIC_BASE_URL"))
    return (override, True) if override else ("anthropic", False)


def service_tier(usage: Any) -> str | None:
    """The card modifier a message's usage selects, or ``None`` for standard."""
    if not isinstance(usage, Mapping):
        return None
    fast = usage.get("speed") == "fast"
    us = usage.get("inference_geo") == "us"
    if fast:
        return "fast_us" if us else "fast"
    return "us" if us else None


def list_priced(model_usage: Any) -> bool:
    """Whether every model's ``costBasis`` is ``list`` (absent: older CLIs, list)."""
    if not isinstance(model_usage, Mapping):
        return True
    for totals in model_usage.values():
        if isinstance(totals, Mapping) and totals.get("costBasis", "list") != "list":
            return False
    return True


def new_traceparent() -> str:
    """A fresh, sampled W3C ``traceparent``."""
    return f"00-{secrets.token_hex(16)}-{secrets.token_hex(8)}-01"


def trace_id(traceparent: Any) -> str | None:
    """The trace id of a well-formed ``traceparent``, or ``None``."""
    parts = str(traceparent or "").strip().split("-")
    if len(parts) != 4 or len(parts[1]) != 32 or len(parts[2]) != 16:
        return None
    if not all(c in "0123456789abcdef" for c in parts[1] + parts[2]) or set(parts[1]) == {"0"}:
        return None
    return parts[1]
