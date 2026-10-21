"""Public, provider-neutral billing records."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any

from opentine.billing._billing_result import BillingResult as BillingResult
from opentine.billing._billing_result import BillingStatus as BillingStatus
from opentine.billing._context import billing_context
from opentine.billing._immutable import freeze
from opentine.billing._rate_json import card_to_dict
from opentine.billing._rate_normalize import normalize_rate_card
from opentine.billing._rate_validation import validate_rate_card, validate_rate_card_data
from opentine.billing._values import as_date as as_date
from opentine.billing._values import as_datetime as as_datetime
from opentine.billing._values import billing_moment as billing_moment
from opentine.billing._values import decimal as decimal

Number = int | float | Decimal
_USAGE_FIELDS = tuple("input output cache_read cache_write_5m cache_write_1h reasoning".split())
_MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_MAGNITUDE = Decimal("1e50")


@dataclass(frozen=True)
class Usage:
    input: int = 0
    output: int = 0
    cache_read: int = 0
    cache_write_5m: int = 0
    cache_write_1h: int = 0
    reasoning: int = 0
    total: int | None = None
    extra: Mapping[str, Number] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in _USAGE_FIELDS:
            if (
                type(getattr(self, name)) is not int
                or not 0 <= getattr(self, name) <= _MAX_SAFE_INTEGER
            ):
                raise ValueError(f"usage.{name} must be a non-negative safe integer")
        if self.total is not None and (
            type(self.total) is not int or not 0 <= self.total <= _MAX_SAFE_INTEGER
        ):
            raise ValueError("usage.total must be a non-negative safe integer")
        normalized: dict[str, Decimal] = {}
        for name, value in self.extra.items():
            if not isinstance(name, str) or not name or name in {*_USAGE_FIELDS, "total", "extra"}:
                raise ValueError(f"invalid or reserved usage.extra dimension: {name!r}")
            try:
                number = decimal(value)
            except (InvalidOperation, ValueError) as exc:
                raise ValueError(f"usage.extra.{name} must be finite and non-negative") from exc
            if not number.is_finite() or number < 0 or number > _MAX_MAGNITUDE:
                raise ValueError(f"usage.extra.{name} must be finite and non-negative")
            normalized[name] = number
        object.__setattr__(self, "extra", freeze(normalized))

    @property
    def input_total(self) -> Number:
        with billing_context():
            extra = sum(
                (
                    decimal(value)
                    for name, value in self.extra.items()
                    if name.startswith(("input_", "cache_read_", "cache_write_"))
                ),
                Decimal("0"),
            )
            return (
                Decimal(self.input)
                + self.cache_read
                + self.cache_write_5m
                + self.cache_write_1h
                + extra
            )

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
                    if value == value.to_integral_value():
                        integer = int(value)
                        value = integer if abs(integer) <= _MAX_SAFE_INTEGER else str(value)
                    else:
                        value = str(value)
                elif type(value) is int and abs(value) > _MAX_SAFE_INTEGER:
                    value = str(value)
                data[name] = value
        if self.total is not None:
            data["total"] = self.total
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Usage:
        raw = dict(data or {})
        known = {name: raw.pop(name, 0) for name in _USAGE_FIELDS}
        total = raw.pop("total", None)
        nested = raw.pop("extra", {})
        extra = {**(nested if isinstance(nested, dict) else {}), **raw}
        return cls(**known, total=total, extra=extra)


@dataclass(frozen=True)
class RateCard:
    id: str
    provider: str
    model: str
    rates: Mapping[str, Decimal]
    aliases: tuple[str, ...] = ()
    effective_from: date = date.min
    effective_until: date | None = None
    context_thresholds: tuple[Mapping[str, Any], ...] = ()
    service_modifiers: Mapping[str, Decimal | Mapping[str, Decimal]] = field(default_factory=dict)
    service_rates: Mapping[str, Mapping[str, Decimal]] = field(default_factory=dict)
    currency: str = "USD"
    currency_to_usd: Decimal = Decimal("1")
    source_urls: tuple[str, ...] = ()
    verified_at: date | None = None
    unmetered: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)
    #: Optional time-of-day rate windows (``opentine-pricing/2``). Last, so no
    #: positional construction of the /1 fields shifts. Empty means "price from
    #: ``rates`` at every hour", which is what every /1 card means.
    schedule: tuple[Mapping[str, Any], ...] = ()
    #: ``opentine-pricing/3`` media fields (see ``billing._media``). Empty means
    #: every dimension is a token dimension with its own rate, as in /1 and /2.
    units: Mapping[str, str] = field(default_factory=dict)
    same_rate_as: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalize_rate_card(self)
        validate_rate_card(self)
        groups = [self.rates, *self.service_rates.values()]
        groups.extend(window["rates"] for window in self.schedule)
        scalars = [self.currency_to_usd]
        for modifier in self.service_modifiers.values():
            groups.append(modifier) if isinstance(modifier, Mapping) else scalars.append(modifier)
        groups.extend((rule.get("multipliers") or {}) for rule in self.context_thresholds)
        rates = [decimal(value) for group in groups for value in group.values()]
        rates.extend(decimal(value) for value in scalars)
        if any(not value.is_finite() or value < 0 or value > _MAX_MAGNITUDE for value in rates):
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
        return card_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RateCard:
        validate_rate_card_data(data)
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
                if isinstance(value, Mapping)
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
            schedule=tuple(data.get("schedule") or ()),
            units=dict(data.get("units") or {}),
            same_rate_as=dict(data.get("same_rate_as") or {}),
        )
