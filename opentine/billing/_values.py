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
