"""Budget enforcement and digest-covered pricing provenance."""

from __future__ import annotations

from typing import Any

from opentine.budget import Budget, BudgetBreach, BudgetExceeded
from opentine.graph import Run, RunStatus, StepKind


class AccountingMixin:
    def _enforce_budget(self, run: Run, budget: Budget) -> bool:
        pricing = run.manifest.get("pricing") or {}
        breach = None
        if budget.strict_cost and pricing.get("complete") is False:
            breach = BudgetBreach("cost_completeness", 1, 0)
        if breach is None:
            breach = budget.check(
                cost=run.total_cost,
                usage=run.total_tokens,
                steps=len(run.steps),
                duration=run.total_duration,
            )
        if breach is None:
            return False
        run.metadata["budget_state"] = {
            "breached": True,
            **breach.to_dict(),
            "cost": run.total_cost,
            "duration": run.total_duration,
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
        if not billing:
            return
        pricing = run.manifest.setdefault("pricing", {})
        if billing.get("catalog_id"):
            pricing.setdefault("catalog_id", billing["catalog_id"])
        if billing.get("catalog_hash"):
            pricing.setdefault("catalog_hash", billing["catalog_hash"])
        if billing.get("catalog_provenance"):
            pricing.setdefault("catalog_provenance", billing["catalog_provenance"])
        if billing.get("rate_card_id"):
            pricing.setdefault("rate_cards", {})[step_id] = billing["rate_card_id"]
        pricing.setdefault("invocations", []).append(
            {
                "calculation": billing.get("calculation", {}),
                "effective_at": billing.get("effective_at"),
                "rate_card_id": billing.get("rate_card_id"),
                "status": billing.get("status", "unknown"),
                "step_id": step_id,
            }
        )
        complete = billing.get("status") in {"complete", "unmetered"}
        pricing["complete"] = bool(pricing.get("complete", True) and complete)

    @staticmethod
    def _warnings(run: Run, response: dict[str, Any]) -> None:
        values = [
            *(response.get("warnings") or []),
            *((response.get("billing") or {}).get("warnings") or []),
        ]
        stored = run.metadata.setdefault("warnings", [])
        for warning in values:
            if warning not in stored:
                stored.append(warning)
