"""Serializable billing outcome record."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal

from opentine.billing._immutable import freeze, thaw

BillingStatus = Literal["complete", "partial", "unknown", "unmetered"]


@dataclass(frozen=True)
class BillingResult:
    status: BillingStatus
    amount_usd: Decimal | None
    known_subtotal_usd: Decimal
    catalog_id: str | None = None
    catalog_hash: str | None = None
    rate_card_id: str | None = None
    effective_at: str | None = None
    warnings: tuple[str, ...] = ()
    calculation: Mapping[str, Any] = field(default_factory=dict)
    catalog_provenance: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "warnings", tuple(self.warnings))
        object.__setattr__(self, "calculation", freeze(self.calculation))
        object.__setattr__(self, "catalog_provenance", tuple(freeze(self.catalog_provenance)))

    @property
    def complete(self) -> bool:
        return self.status in ("complete", "unmetered")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "amount_usd": str(self.amount_usd) if self.amount_usd is not None else None,
            "known_subtotal_usd": str(self.known_subtotal_usd),
            "catalog_id": self.catalog_id,
            "catalog_hash": self.catalog_hash,
            "rate_card_id": self.rate_card_id,
            "effective_at": self.effective_at,
            "warnings": list(self.warnings),
            "calculation": thaw(self.calculation),
            "catalog_provenance": thaw(self.catalog_provenance),
        }
