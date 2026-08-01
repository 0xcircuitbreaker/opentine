"""Recording usage for managed re-hosts whose regional rates are not priced.

Bedrock, Vertex, and Azure OpenAI resell the same models under per-region,
per-account contract pricing that no public snapshot can state truthfully. The
bundled signed catalog therefore carries no card for these providers (see
``tests/test_managed_cloud_pricing.py``, which makes that permanent), so the
engine's no-card path already returns ``status='unknown'``. This module is the
adapter-side half: it makes that silence explicit and auditable rather than
leaving a ``0`` that reads like a bill.

The invariant it defends: usage is always recorded, cost is only ever claimed
when something the operator supplied actually priced the call.
"""

from __future__ import annotations

from typing import Any

MANAGED_UNPRICED = "managed_cloud_unpriced"
USER_SUPPLIED = "user_supplied_regional_rates"
_PRICED_STATUSES = {"complete", "partial", "unmetered"}


def reject_unsupported_controls(surface: str, **controls: Any) -> None:
    """Refuse request knobs a managed surface does not expose.

    Bedrock's and Vertex's Anthropic Messages surfaces have neither
    ``service_tier`` nor ``inference_geo``: the re-host's contract, not the
    request, decides capacity and geography. Accepting the argument and dropping
    it would leave the caller believing they asked for a tier they never got —
    and, for ``inference_geo``, would change how the tier is priced. Raising is
    the only honest answer.
    """
    named = sorted(name for name, control in controls.items() if control is not None)
    if named:
        raise ValueError(
            f"{surface} has no {' or '.join(named)}; the managed re-host's contract "
            "sets capacity and region, not the request"
        )


def unpriced_warning(provider: str) -> str:
    return (
        f"{provider} regional rates are not in the signed catalog; "
        "usage is recorded and cost is unknown"
    )


def managed_unpriced(
    payload: dict[str, Any], *, provider: str, region: str | None = None
) -> dict[str, Any]:
    """Stamp a managed-cloud payload with why its cost is (or is not) known.

    Mutates and returns ``payload`` as produced by ``metered_response``.

    When the operator supplied ``rates=`` or an overlay card, the call *is*
    priced: this no-ops on the numbers and only records the basis, because a
    caller-priced managed call is exactly as trustworthy as the rates behind it.

    Otherwise the engine must already have taken the no-card path. Anything else
    means a rate card priced a managed provider — the mispricing this release
    exists to prevent — so it raises rather than publish a plausible number.
    """
    billing = payload["billing"]
    calculation = billing.setdefault("calculation", {})
    if region:
        calculation["managed_region"] = region
    if billing.get("rate_card_id") is not None or billing.get("status") in _PRICED_STATUSES:
        calculation["pricing_basis"] = USER_SUPPLIED
        return payload
    if billing.get("status") != "unknown":
        raise RuntimeError(
            f"managed provider {provider!r} was billed with status "
            f"{billing.get('status')!r}; expected the unpriced no-card path"
        )
    calculation["pricing_basis"] = MANAGED_UNPRICED
    warning = unpriced_warning(provider)
    if warning not in billing.setdefault("warnings", []):
        billing["warnings"].append(warning)
    return payload
