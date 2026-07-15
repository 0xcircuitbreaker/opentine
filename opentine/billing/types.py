"""Public, provider-neutral billing records."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any, Literal

BillingStatus = Literal["complete", "partial", "unknown", "unmetered"]
Number = int | float | Decimal


def decimal(value: Any, default: str = "0") -> Decimal:
    if value is None:
        return Decimal(default)
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value))


def as_date(value: date | datetime | str | None) -> date:
    if value is None:
        return datetime.now(UTC).date()
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(value[:10])


@dataclass(frozen=True)
class Usage:
    input: int = 0
    output: int = 0
    cache_read: int = 0
    cache_write_5m: int = 0
    cache_write_1h: int = 0
    reasoning: int = 0
    total: int | None = None
    extra: dict[str, Number] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in (
            "input",
            "output",
            "cache_read",
            "cache_write_5m",
            "cache_write_1h",
            "reasoning",
        ):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError(f"usage.{name} must be a non-negative integer")
        if self.total is not None and (type(self.total) is not int or self.total < 0):
            raise ValueError("usage.total must be a non-negative integer")
        for name, value in self.extra.items():
            number = decimal(value)
            if not number.is_finite() or number < 0:
                raise ValueError(f"usage.extra.{name} must be finite and non-negative")

    @property
    def input_total(self) -> Number:
        extra = sum(
            (
                decimal(value)
                for name, value in self.extra.items()
                if name.startswith(("input_", "cache_read_", "cache_write_"))
            ),
            Decimal("0"),
        )
        return self.input + self.cache_read + self.cache_write_5m + self.cache_write_1h + extra

    def dimensions(self) -> dict[str, Number]:
        values: dict[str, Number] = {
            "input": self.input,
            "output": self.output,
            "cache_read": self.cache_read,
            "cache_write_5m": self.cache_write_5m,
            "cache_write_1h": self.cache_write_1h,
            "reasoning": self.reasoning,
        }
        values.update(self.extra)
        return values

    def to_dict(self, *, compact: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {}
        for name, value in self.dimensions().items():
            if value or not compact:
                if isinstance(value, Decimal):
                    value = int(value) if value == value.to_integral_value() else float(value)
                data[name] = value
        if self.total is not None:
            data["total"] = self.total
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Usage:
        raw = dict(data or {})
        known = {
            name: int(raw.pop(name, 0) or 0)
            for name in (
                "input",
                "output",
                "cache_read",
                "cache_write_5m",
                "cache_write_1h",
                "reasoning",
            )
        }
        total = raw.pop("total", None)
        nested = raw.pop("extra", {})
        extra = {**(nested if isinstance(nested, dict) else {}), **raw}
        return cls(**known, total=int(total) if total is not None else None, extra=extra)


@dataclass(frozen=True)
class RateCard:
    id: str
    provider: str
    model: str
    rates: dict[str, Decimal]
    aliases: tuple[str, ...] = ()
    effective_from: date = date.min
    effective_until: date | None = None
    context_thresholds: tuple[dict[str, Any], ...] = ()
    service_modifiers: dict[str, Decimal | dict[str, Decimal]] = field(default_factory=dict)
    service_rates: dict[str, dict[str, Decimal]] = field(default_factory=dict)
    currency: str = "USD"
    currency_to_usd: Decimal = Decimal("1")
    source_urls: tuple[str, ...] = ()
    verified_at: date | None = None
    unmetered: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        groups = [self.rates, *self.service_rates.values()]
        scalars = [self.currency_to_usd]
        for modifier in self.service_modifiers.values():
            groups.append(modifier) if isinstance(modifier, dict) else scalars.append(modifier)
        groups.extend((rule.get("multipliers") or {}) for rule in self.context_thresholds)
        rates = [decimal(value) for group in groups for value in group.values()]
        if any(not value.is_finite() or value < 0 for value in rates):
            raise ValueError("rate-card values must be finite and non-negative")
        conversion = decimal(self.currency_to_usd)
        if not conversion.is_finite() or conversion <= 0:
            raise ValueError("currency conversion must be finite and positive")

    def active(self, when: date) -> bool:
        return self.effective_from <= when and (
            self.effective_until is None or when <= self.effective_until
        )

    def matches(self, provider: str, model: str) -> bool:
        names = (self.model, *self.aliases)
        return self.provider.casefold() == provider.casefold() and model.casefold() in {
            item.casefold() for item in names
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "provider": self.provider,
            "model": self.model,
            "aliases": list(self.aliases),
            "effective_from": self.effective_from.isoformat(),
            "effective_until": self.effective_until.isoformat() if self.effective_until else None,
            "rates": {key: str(value) for key, value in sorted(self.rates.items())},
            "context_thresholds": list(self.context_thresholds),
            "service_modifiers": {
                key: {name: str(rate) for name, rate in sorted(value.items())}
                if isinstance(value, dict)
                else str(value)
                for key, value in sorted(self.service_modifiers.items())
            },
            "service_rates": {
                tier: {name: str(rate) for name, rate in sorted(rates.items())}
                for tier, rates in sorted(self.service_rates.items())
            },
            "currency": self.currency,
            "currency_to_usd": str(self.currency_to_usd),
            "source_urls": list(self.source_urls),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "unmetered": self.unmetered,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RateCard:
        return cls(
            id=data["id"],
            provider=data["provider"],
            model=data["model"],
            aliases=tuple(data.get("aliases") or ()),
            effective_from=as_date(data.get("effective_from") or date.min),
            effective_until=as_date(data["effective_until"])
            if data.get("effective_until")
            else None,
            rates={key: decimal(value) for key, value in (data.get("rates") or {}).items()},
            context_thresholds=tuple(data.get("context_thresholds") or ()),
            service_modifiers={
                key: {name: decimal(rate) for name, rate in value.items()}
                if isinstance(value, dict)
                else decimal(value)
                for key, value in (data.get("service_modifiers") or {}).items()
            },
            service_rates={
                tier: {name: decimal(rate) for name, rate in rates.items()}
                for tier, rates in (data.get("service_rates") or {}).items()
            },
            currency=data.get("currency", "USD"),
            currency_to_usd=decimal(data.get("currency_to_usd"), "1"),
            source_urls=tuple(data.get("source_urls") or ()),
            verified_at=as_date(data["verified_at"]) if data.get("verified_at") else None,
            unmetered=bool(data.get("unmetered", False)),
            metadata=dict(data.get("metadata") or {}),
        )


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
    calculation: dict[str, Any] = field(default_factory=dict)
    catalog_provenance: tuple[dict[str, Any], ...] = ()

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
            "calculation": self.calculation,
            "catalog_provenance": list(self.catalog_provenance),
        }
