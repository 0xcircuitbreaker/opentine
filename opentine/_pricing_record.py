"""Reading the billable facts off one recorded step, and billing them.

Split out of :mod:`opentine._pricing_pass` so the pass itself stays a rollup.
Everything here answers the same question from two carriers of the same record
-- a ``Step`` and a ``TraceEvent`` -- so ``tine price`` and ``tine import
--price`` keep sharing one pricing path.
"""

from __future__ import annotations

import math
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from opentine.billing import PricingCatalog, Usage, bill
from opentine.billing._billing_result import BillingResult

UNKNOWN = "unknown"


def read_record(step: Any) -> tuple[str, str, str, dict[str, Any], str]:
    """Read ``(kind, provider, model, usage, id)`` off a ``Step`` or ``TraceEvent``.

    The two carriers spell two of them differently (``model_info``/``model``,
    ``id``/``span_id``); reading both here is what lets the two commands share
    one pass.
    """
    # A repository-loaded step keeps a kind the legacy enum lacks in v3_kind
    # (a subagent roll-up loads as "model"); that is the kind that decides billing.
    kind = getattr(step, "v3_kind", None) or getattr(step, "kind", "")
    model = getattr(step, "model_info", None)
    identifier = getattr(step, "id", None) or getattr(step, "span_id", "")
    return (
        str(getattr(kind, "value", kind) or ""),
        str(getattr(step, "provider", "") or ""),
        str((model if model is not None else getattr(step, "model", "")) or ""),
        dict(getattr(step, "usage", None) or {}),
        str(identifier),
    )


#: Kinds the runtime gives a model call by what it answered: the final answer is
#: ``done``, text beside tool calls is ``think``, a refusal or a failed call is
#: ``error``. Each is still one billed call, so ``tine price`` must not skip it
#: (it used to: a ``tine run --model`` run, one ``done`` step, priced at $0).
CALL_KINDS = frozenset({"done", "think", "error"})


def recorded_status(step: Any) -> str | None:
    """The billing status the capture recorded on *step*, or ``None`` if none."""
    billing = getattr(step, "billing", None)
    status = billing.get("status") if isinstance(billing, dict) else None
    return status if isinstance(status, str) and status else None


def verdict_status(step: Any) -> str | None:
    """The status re-pricing may trust for an ``unmetered`` decision.

    ``None`` only when the step carries no billing block at all (a harness
    capture). A block with a missing, empty, or non-string status is not "no
    verdict": it is unreadable, so it reads as ``unknown`` and never as free
    (final security pass 3, #2/#3 -- an imported ``{"status": ""}`` booked $0).
    """
    if not getattr(step, "billing", None):
        return None
    status = recorded_status(step)
    return status or "unknown"


def billable(kind: str, step: Any, priceable: frozenset[str]) -> bool:
    """Whether *step* is a model call: a ``model`` step, or a call-shaped step
    the capture itself billed (it carries usage, a provider, and a meter)."""
    if kind in priceable:
        return True
    if kind not in CALL_KINDS or not getattr(step, "usage", None):
        return False
    billing = getattr(step, "billing", None)
    calculation = billing.get("calculation") if isinstance(billing, dict) else None
    return bool(getattr(step, "provider", "")) and isinstance(calculation, dict)


def record_tier(step: Any) -> str | None:
    """The service tier a step was billed at (``fast``, ``us``, ``flex``…), if recorded.

    Native capture keeps it in ``billing.calculation.service_tier``; a harness
    capture (Claude Code fast mode) in ``inputs.service_tier``. Re-pricing without
    it billed a fast-mode call at 1x.
    """
    billing = getattr(step, "billing", None)
    calculation = billing.get("calculation") if isinstance(billing, dict) else None
    inputs = getattr(step, "inputs", None)
    for source in (calculation, inputs):
        tier = source.get("service_tier") if isinstance(source, dict) else None
        if isinstance(tier, str) and 0 < len(tier) <= 64:
            return tier
    return None


def record_moment(step: Any) -> datetime | None:
    """The instant a step was recorded, in UTC, or ``None`` if it recorded none.

    Both carriers hold epoch seconds, and ``Step.timestamp`` *defaults* to 0.0 --
    so 0 has to read as "not recorded" rather than as 1970, which would price
    every timestamp-less step against cards that did not exist yet.
    """
    raw = getattr(step, "timestamp", None)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(raw):
        return None
    if raw <= 0:
        return None
    try:
        return datetime.fromtimestamp(raw, UTC)
    except (OSError, OverflowError, ValueError):
        return None


def bill_record(
    provider: str,
    model: str,
    usage: dict[str, Any],
    *,
    catalog: PricingCatalog,
    when: date,
    billed_at: datetime | None = None,
    service_tier: str | None = None,
    unmetered: bool = False,
) -> BillingResult:
    """Bill one record: ``when`` selects the card, ``billed_at`` the rate window.

    ``unmetered`` books the call at $0 with no card; the caller decides it from
    the record (:func:`opentine._local_providers.unmetered_call`), never from a
    provider name alone.
    """
    # No usage recorded at all (streamed/errored spans often carry none) is
    # "unknown", not a $0 bill — billing an empty dict fabricates a "complete" $0.
    if usage:
        try:
            return bill(
                provider,
                model,
                Usage.from_dict(usage),
                catalog=catalog,
                effective_at=when,
                billed_at=billed_at,
                service_tier=service_tier,
                unmetered=unmetered,
            )
        except (TypeError, ValueError):
            pass
    return BillingResult(
        UNKNOWN,
        None,
        Decimal("0"),
        catalog.id,
        catalog.hash,
        effective_at=when.isoformat(),
        warnings=("no billable usage recorded; price is unknown",),
    )
