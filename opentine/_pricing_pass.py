"""Post-hoc pricing: cost as a pure function of the recorded run.

:func:`opentine.billing.bill` has always been the pricing primitive, but its
only caller lived inside adapter capture (``opentine.models._metered``). A run
that was *imported* rather than executed therefore recorded ``(provider, model,
usage)`` and no cost at all, so summing recorded costs showed ``$0.00`` where
the live path said ``unknown``. This module is the second caller: it re-derives
an already-recorded run's price from the catalog through the same ``bill()``.

Two rules the pass may never break:

* **Never invent a zero.** ``bill()`` answers ``status="unknown"`` with
  ``amount_usd=None`` when no rate card matches, and that answer is carried
  through verbatim: an uncarded step is reported and counted as *unknown*, never
  as free. It is kept out of ``by_model``/``by_provider`` for the same reason --
  a ``0.0`` beside a model name reads as "free" -- and named in
  ``unknown_models`` instead. The total sums *known* subtotals only.
* **Never rewrite the record.** A priced run is a *report* (``tine price``); a
  price is written only by :func:`price_events`, onto a fresh import that no store
  has seen. Rewriting a stored content-addressed event would change its id.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from opentine._import_billing import without_source_cost
from opentine._local_providers import harness_run, unmetered_call
from opentine._pricing_record import (
    bill_record,
    billable,
    read_record,
    record_moment,
    record_tier,
    verdict_status,
)
from opentine.billing import PricingCatalog, load_catalogs
from opentine.billing._context import billing_context
from opentine.billing.types import as_date

#: Only a model call meets a rate card. A tool or think step is not "free", it is
#: not a billable call, so it is left out of the rollup rather than counted as 0.
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


def _card_date(when: date, moment: datetime | None, pinned: bool) -> date:
    """Which day's rate card prices this step.

    ``tine price --at DATE`` pins it for the whole run. Unpinned, a step is carded
    on the day it was recorded (the pass's as-of date without a timestamp); the
    *window* within the card always comes from the step's own instant.
    """
    return when if pinned or moment is None else moment.date()


def price_steps(
    steps: Iterable[Any],
    *,
    effective_at: date | datetime | str | None = None,
    catalog: PricingCatalog | None = None,
    harness_capture: bool = False,
) -> RunPricing:
    """Price every model step from the catalog; report, never write."""
    selected = catalog or load_catalogs()
    when = as_date(effective_at)
    pinned = effective_at is not None
    prices: list[StepPrice] = []
    by_model: dict[str, Decimal] = {}
    by_provider: dict[str, Decimal] = {}
    counts: dict[str, int] = {}
    unpriced: set[str] = set()
    total = Decimal("0")
    with billing_context():
        for step in steps:
            kind, provider, model, usage, identifier = read_record(step)
            if not billable(kind, step, PRICEABLE_KINDS):
                continue
            moment = record_moment(step)
            result = bill_record(
                provider,
                model,
                usage,
                catalog=selected,
                when=_card_date(when, moment, pinned),
                billed_at=moment,
                service_tier=record_tier(step),
                unmetered=unmetered_call(
                    provider, model, verdict_status(step), harness_capture=harness_capture
                ),
            )
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
    capture = harness_run(run)  # positive evidence for a billing-less local call
    return price_steps(
        run.steps, effective_at=effective_at, catalog=catalog, harness_capture=capture
    )


def price_events(
    events: Sequence[Any],
    *,
    effective_at: date | datetime | str | None = None,
    catalog: PricingCatalog | None = None,
) -> list[Any]:
    """Return copies of *events* carrying the catalog's price.

    Called on freshly parsed trace events, before anything is written, so this
    is initial recording rather than mutation -- the inputs are plain frozen
    dataclasses that no store has seen. A step the catalog cannot price keeps no
    cost from its source (final security pass 5, #6: the file's own figure moves
    to ``opentine.source_reported_cost``) and gains an ``unknown`` record when it
    carried no billing. An imported provider is a label: never ``unmetered``.
    """
    selected = catalog or load_catalogs()
    when = as_date(effective_at)
    pinned = effective_at is not None
    priced: list[Any] = []
    for event in events:
        kind, provider, model, usage, _ = read_record(event)
        if not billable(kind, event, PRICEABLE_KINDS):
            priced.append(event)
            continue
        moment = record_moment(event)
        result = bill_record(
            provider,
            model,
            usage,
            catalog=selected,
            when=_card_date(when, moment, pinned),
            billed_at=moment,
            service_tier=record_tier(event),
        )
        if result.status in PRICED_STATUSES:
            priced.append(
                replace(event, cost=float(result.known_subtotal_usd), billing=result.to_dict())
            )
        elif not getattr(event, "billing", None):
            priced.append(replace(without_source_cost(event), billing=result.to_dict()))
        else:
            priced.append(without_source_cost(event))
    return priced
