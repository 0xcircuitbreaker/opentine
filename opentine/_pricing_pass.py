"""Post-hoc pricing: cost as a pure function of the recorded run.

:func:`opentine.billing.bill` has always been the pricing primitive, but its
only caller lived inside adapter capture (``opentine.models._metered``). A run
that was *imported* rather than executed therefore recorded ``(provider, model,
usage)`` and no cost at all, and anything summing the recorded costs showed an
honest-looking ``$0.00`` exactly where the live path would have said
``unknown``. This module is the second caller: it re-derives the price of an
already-recorded run from the catalog, and it bottoms out in the same
``bill()``, so there is one pricing arithmetic in the codebase, not two.

Two rules the pass may never break:

* **Never invent a zero.** ``bill()`` answers ``status="unknown"`` with
  ``amount_usd=None`` when no rate card matches, and that answer is carried
  through verbatim: an uncarded step is reported and counted as *unknown*, never
  as free. It is kept out of ``by_model``/``by_provider`` for the same reason --
  a ``0.0`` beside a model name reads as "free" -- and named in
  ``unknown_models`` instead. The total sums *known* subtotals only.
* **Never rewrite the record.** A priced run is a *report* (``tine price``). The
  only place a price is written is onto records that have not been stored yet --
  :func:`price_events`, on a fresh import, which is initial recording, not
  mutation. Rewriting a stored content-addressed event would change its id.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from opentine.billing import PricingCatalog, Usage, bill, load_catalogs
from opentine.billing._billing_result import BillingResult
from opentine.billing._context import billing_context
from opentine.billing.types import as_date

#: Only a model call meets a rate card. A tool or think step is not "free", it
#: is simply not a billable call, so it is left out of the rollup entirely
#: rather than counted as a zero.
PRICEABLE_KINDS = frozenset({"model"})
UNKNOWN = "unknown"
#: Statuses that mean the catalog actually answered for this step.
PRICED_STATUSES = frozenset({"complete", "partial", "unmetered"})


@dataclass(frozen=True)
class StepPrice:
    """What the catalog says one recorded step cost, verbatim from ``bill()``."""

    step_id: str
    provider: str
    model: str
    status: str
    amount_usd: float | None
    known_subtotal_usd: float
    rate_card_id: str | None
    billing: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "provider": self.provider,
            "model": self.model,
            "status": self.status,
            "amount_usd": self.amount_usd,
            "known_subtotal_usd": self.known_subtotal_usd,
            "rate_card_id": self.rate_card_id,
        }


@dataclass(frozen=True)
class RunPricing:
    """The rollup of a post-hoc pass, naming the catalog it priced against."""

    catalog_id: str | None
    catalog_hash: str | None
    effective_at: str
    total_cost: float
    steps: tuple[StepPrice, ...]
    by_model: dict[str, float]
    by_provider: dict[str, float]
    status_counts: dict[str, int]
    #: Models the catalog could not price at all. Named, not zeroed.
    unknown_models: tuple[str, ...] = ()

    @property
    def priced_steps(self) -> int:
        return sum(count for name, count in self.status_counts.items() if name in PRICED_STATUSES)

    @property
    def unknown_steps(self) -> int:
        return self.status_counts.get(UNKNOWN, 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "catalog_id": self.catalog_id,
            "catalog_hash": self.catalog_hash,
            "effective_at": self.effective_at,
            "total_cost": self.total_cost,
            "priced_steps": self.priced_steps,
            "unknown_steps": self.unknown_steps,
            "unknown_models": list(self.unknown_models),
            "by_model": dict(self.by_model),
            "by_provider": dict(self.by_provider),
            "status_counts": dict(self.status_counts),
            "steps": [price.to_dict() for price in self.steps],
        }


def _record(step: Any) -> tuple[str, str, str, dict[str, Any], str]:
    """Read ``(kind, provider, model, usage, id)`` off a ``Step`` or a ``TraceEvent``.

    The two carriers of the same recorded facts spell two of them differently
    (``model_info``/``model``, ``id``/``span_id``); reading both here is what
    lets ``tine price`` and ``tine import --price`` share one pass.
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


def _bill_record(
    provider: str, model: str, usage: dict[str, Any], *, catalog: PricingCatalog, when: date
) -> BillingResult:
    # No usage recorded at all (streamed/errored spans often carry none) is
    # "unknown", not a $0 bill — billing an empty dict fabricates a "complete" $0.
    if usage:
        try:
            return bill(provider, model, Usage.from_dict(usage), catalog=catalog, effective_at=when)
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


def price_steps(
    steps: Iterable[Any],
    *,
    effective_at: date | datetime | str | None = None,
    catalog: PricingCatalog | None = None,
) -> RunPricing:
    """Price every model step from the catalog; report, never write."""
    selected = catalog or load_catalogs()
    when = as_date(effective_at)
    prices: list[StepPrice] = []
    by_model: dict[str, Decimal] = {}
    by_provider: dict[str, Decimal] = {}
    counts: dict[str, int] = {}
    unpriced: set[str] = set()
    total = Decimal("0")
    with billing_context():
        for step in steps:
            kind, provider, model, usage, identifier = _record(step)
            if kind not in PRICEABLE_KINDS:
                continue
            result = _bill_record(provider, model, usage, catalog=selected, when=when)
            known = Decimal(str(result.known_subtotal_usd))
            prices.append(
                StepPrice(
                    identifier,
                    provider,
                    model,
                    result.status,
                    None if result.amount_usd is None else float(result.amount_usd),
                    float(known),
                    result.rate_card_id,
                    result.to_dict(),
                )
            )
            counts[result.status] = counts.get(result.status, 0) + 1
            total += known
            if result.status not in PRICED_STATUSES:
                unpriced.add(model)
                continue
            by_model[model] = by_model.get(model, Decimal("0")) + known
            by_provider[provider] = by_provider.get(provider, Decimal("0")) + known
    return RunPricing(
        catalog_id=selected.id,
        catalog_hash=selected.hash,
        effective_at=when.isoformat(),
        total_cost=float(total),
        steps=tuple(prices),
        by_model={name: float(value) for name, value in by_model.items()},
        by_provider={name: float(value) for name, value in by_provider.items()},
        status_counts=counts,
        unknown_models=tuple(sorted(unpriced)),
    )


def price_run(
    run: Any,
    *,
    effective_at: date | datetime | str | None = None,
    catalog: PricingCatalog | None = None,
) -> RunPricing:
    """Re-price a recorded run. Read-only: the run is not touched."""
    return price_steps(run.steps, effective_at=effective_at, catalog=catalog)


def price_events(
    events: Sequence[Any],
    *,
    effective_at: date | datetime | str | None = None,
    catalog: PricingCatalog | None = None,
) -> list[Any]:
    """Return copies of *events* carrying the catalog's price.

    Called on freshly parsed trace events, before anything is written, so this
    is initial recording rather than mutation -- the inputs are plain frozen
    dataclasses that no store has seen. When the catalog cannot price a step the
    event's own recorded cost is kept (a pass that cannot price must not erase
    what the source reported), and the unknown billing record is attached only
    when the event carried none, so a bare import gains an honest ``unknown``
    instead of an implicit zero.
    """
    selected = catalog or load_catalogs()
    when = as_date(effective_at)
    priced: list[Any] = []
    for event in events:
        kind, provider, model, usage, _ = _record(event)
        if kind not in PRICEABLE_KINDS:
            priced.append(event)
            continue
        result = _bill_record(provider, model, usage, catalog=selected, when=when)
        if result.status in PRICED_STATUSES:
            priced.append(
                replace(event, cost=float(result.known_subtotal_usd), billing=result.to_dict())
            )
        elif not getattr(event, "billing", None):
            priced.append(replace(event, billing=result.to_dict()))
        else:
            priced.append(event)
    return priced
