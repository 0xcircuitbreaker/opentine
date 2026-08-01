"""Budget enforcement and digest-covered pricing provenance."""

from __future__ import annotations

from typing import Any

from opentine.budget import Budget, BudgetBreach, BudgetExceeded
from opentine.graph import Run, RunStatus, StepKind

_MISSING = object()


def _container(owner: dict[str, Any], key: str, kind: type, default: Any) -> tuple[Any, bool]:
    """Return a shape-correct container for ``owner[key]``, and whether one was replaced.

    A manifest and metadata are operator-editable and only partly typed by
    ``validate_run_record``, so a default that rescues absence (``or {}``,
    ``setdefault``) still hands a scalar to ``.get``/``.append``/``[key] =``. Absence
    and a wrong shape are treated as the same case -- "no usable prior record" -- but
    only the second reports ``True``, because a replaced container must never back a
    positive cost-completeness claim.
    """
    value = owner.get(key, _MISSING)
    if isinstance(value, kind):
        return value, False
    owner[key] = default
    return default, value is not _MISSING


def _listed(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def pricing_summary(run: Run) -> dict[str, Any]:
    """Summarize how much of a run's cost is actually known.

    The reader half of ``_pin_billing``: it answers only from what that writer
    pins into ``manifest['pricing']``, so a run recorded before this existed
    (every pre-0.6.0 artifact) degrades to a complete, zero-unpriced summary
    rather than reporting an absent record as a defect.

    ``complete`` is conjunctive with the step census on purpose. The pinned flag
    is operator-editable; a summary that claimed completeness while listing
    unpriced steps would be a false trust signal in exactly the case that
    matters.
    """
    pricing = run.manifest.get("pricing")
    pricing = pricing if isinstance(pricing, dict) else {}
    invocations = [item for item in _listed(pricing.get("invocations")) if isinstance(item, dict)]
    unpriced = [item for item in invocations if item.get("status") not in {"complete", "unmetered"}]
    providers = set()
    for item in unpriced:
        calculation = item.get("calculation")
        provider = calculation.get("provider") if isinstance(calculation, dict) else None
        if isinstance(provider, str) and provider:
            providers.add(provider)
    return {
        "complete": pricing.get("complete", True) is True and not unpriced,
        "unpriced_steps": len(unpriced),
        "unpriced_providers": sorted(providers),
    }


class AccountingMixin:
    def _enforce_budget(
        self,
        run: Run,
        budget: Budget,
        *,
        elapsed_duration: float | None = None,
    ) -> bool:
        pricing = run.manifest.get("pricing")
        pricing = pricing if isinstance(pricing, dict) else {}
        duration = max(run.total_duration, elapsed_duration or 0)
        breach = None
        # Absent means "nothing recorded yet", so it passes; anything that is not
        # literally True (False, 0, "false", null) is not a proven-complete claim.
        if budget.strict_cost and pricing.get("complete", True) is not True:
            breach = BudgetBreach("cost_completeness", 1, 0)
        if breach is None:
            breach = budget.check(
                cost=run.total_cost,
                usage=run.total_tokens,
                steps=len(run.steps),
                duration=duration,
            )
        if breach is None:
            return False
        run.metadata["budget_state"] = {
            "breached": True,
            **breach.to_dict(),
            "cost": run.total_cost,
            "duration": duration,
            "steps": len(run.steps),
            "usage": run.total_tokens,
        }
        run.add_step(
            StepKind.error,
            {"text": f"Budget exceeded: {breach.dimension}"},
            error={"type": "BudgetExceeded", **breach.to_dict()},
        )
        run.status = RunStatus.failed
        if budget.on_breach == "raise":
            raise BudgetExceeded(breach, run=run)
        return True

    @staticmethod
    def _pin_billing(run: Run, step_id: str, billing: dict[str, Any]) -> None:
        if not isinstance(billing, dict) or not billing:
            return  # a provider may hand back any JSON value under "billing"
        pricing, damaged = _container(run.manifest, "pricing", dict, {})
        if billing.get("catalog_id"):
            pricing.setdefault("catalog_id", billing["catalog_id"])
        if billing.get("catalog_hash"):
            pricing.setdefault("catalog_hash", billing["catalog_hash"])
        if billing.get("catalog_provenance"):
            pricing.setdefault("catalog_provenance", billing["catalog_provenance"])
        snapshot = {
            "catalog_id": billing.get("catalog_id"),
            "catalog_hash": billing.get("catalog_hash"),
            "catalog_provenance": billing.get("catalog_provenance") or [],
        }
        catalogs, broke = _container(pricing, "catalogs", list, [])
        damaged = damaged or broke
        if (snapshot["catalog_id"] or snapshot["catalog_hash"]) and snapshot not in catalogs:
            catalogs.append(snapshot)
        if billing.get("rate_card_id"):
            cards, broke = _container(pricing, "rate_cards", dict, {})
            damaged = damaged or broke
            cards[step_id] = billing["rate_card_id"]
        invocations, broke = _container(pricing, "invocations", list, [])
        damaged = damaged or broke
        invocations.append(
            {
                "calculation": billing.get("calculation", {}),
                "catalog_hash": billing.get("catalog_hash"),
                "catalog_id": billing.get("catalog_id"),
                "effective_at": billing.get("effective_at"),
                "rate_card_id": billing.get("rate_card_id"),
                "status": billing.get("status", "unknown"),
                "step_id": step_id,
            }
        )
        complete = billing.get("status") in {"complete", "unmetered"}
        # `and` on the raw prior laundered a malformed "false" into a positive claim.
        prior = pricing.get("complete", True) is True
        pricing["complete"] = prior and complete and not damaged

    @staticmethod
    def _warnings(run: Run, response: dict[str, Any]) -> None:
        billing = response.get("billing")
        values = [
            *_listed(response.get("warnings")),
            *_listed(billing.get("warnings") if isinstance(billing, dict) else None),
        ]
        stored, _ = _container(run.metadata, "warnings", list, [])
        for warning in values:
            if warning not in stored:
                stored.append(warning)
