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
    kind = getattr(step, "kind", "")
    model = getattr(step, "model_info", None)
    identifier = getattr(step, "id", None) or getattr(step, "span_id", "")
    return (
        str(getattr(kind, "value", kind) or ""),
        str(getattr(step, "provider", "") or ""),
        str((model if model is not None else getattr(step, "model", "")) or ""),
        dict(getattr(step, "usage", None) or {}),
        str(identifier),
    )


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
) -> BillingResult:
    """Bill one record: ``when`` selects the card, ``billed_at`` the rate window."""
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
