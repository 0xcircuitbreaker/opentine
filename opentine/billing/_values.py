"""Shared conversion helpers for billing value objects."""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any


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
        return value.astimezone(UTC).date() if value.tzinfo is not None else value.date()
    if isinstance(value, date):
        return value
    # Truncating to value[:10] drops any offset, so "2026-07-25T23:00-08:00" was
    # read as the 25th when in UTC it is already the 26th — a rate-card boundary
    # can fall between the two. Parse the full timestamp when there is one so the
    # string path agrees with the datetime path above.
    try:
        return as_date(datetime.fromisoformat(value))
    except ValueError:
        return date.fromisoformat(value[:10])


def as_datetime(value: date | datetime | str | None) -> datetime | None:
    """The billing *moment* in UTC, or ``None`` when the input carries no time.

    A plain ``date`` (or a date-only string) is a day, not an instant: there is
    no time of day in it to place inside a time-of-day rate window, so it
    answers ``None`` and the engine falls back to a card's base rates. A missing
    value is "now", which does have a time of day. Naive datetimes are read as
    UTC rather than shifted, matching how :func:`as_date` takes their date.
    """
    if value is None:
        return datetime.now(UTC)
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, date):
        return None
    if len(value) <= 10 or not ("T" in value or "t" in value or " " in value):
        return None
    try:
        return as_datetime(datetime.fromisoformat(value))
    except ValueError:
        return None


def billing_moment(value: date | datetime | str | None) -> tuple[date, datetime | None]:
    """Split a billing input into (card-selection date, rate-window moment).

    One clock read: deriving the two separately from ``None`` could straddle
    midnight and price a step against a different day than it was carded on.
    """
    moment = as_datetime(value)
    return as_date(moment if moment is not None else value), moment
