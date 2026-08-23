"""Time-of-day (peak/off-peak) rate windows for a rate card.

``opentine-pricing/2`` adds one optional field to a rate card: ``schedule``, an
ordered list of windows. Each window names the UTC hour ranges it covers, the
days it covers (``all``/``weekday``/``weekend``), and the rates that replace the
card's base rates inside it. The first window covering a billing moment wins.

The design is deliberately *additive by absence*:

* A card with no ``schedule`` -- every card written against
  ``opentine-pricing/1`` -- holds an empty tuple, matches no window, and prices
  from ``rates`` exactly as it always has, to the cent.
* A scheduled card priced from a *date* rather than an instant also falls back
  to ``rates``, because a day has no time of day to place in a window.

So the base ``rates`` are the out-of-window price. For DeepSeek that is the
off-peak price, with a single ``peak`` window carrying the higher rates -- the
representation that reads correctly if a window is ever dropped.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from opentine.billing._immutable import freeze
from opentine.billing._values import decimal

#: Which days of the week a window covers.
DAY_SCOPES = ("all", "weekday", "weekend")
_MINUTES_PER_DAY = 24 * 60


def _minutes(value: Any) -> int:
    """Parse an ``"HH:MM"`` UTC wall-clock string into minutes past midnight."""
    if not isinstance(value, str):
        raise ValueError("rate-card schedule hours must be 'HH:MM' UTC strings")
    parts = value.split(":")
    if len(parts) != 2 or not all(
        len(part) == 2 and part.isascii() and part.isdigit() for part in parts
    ):
        raise ValueError("rate-card schedule hours must be 'HH:MM' UTC strings")
    minutes = int(parts[0]) * 60 + int(parts[1])
    # 24:00 is a legal *end*: it is midnight at the far edge of the same day,
    # which "00:00" cannot say without reading as an empty or wrapping window.
    if not 0 <= minutes <= _MINUTES_PER_DAY:
        raise ValueError("rate-card schedule hours must be within a day")
    return minutes


def _ranges(raw: Any) -> tuple[tuple[int, int], ...]:
    if not isinstance(raw, (list, tuple)) or not raw:
        raise ValueError("rate-card schedule window needs a non-empty hours list")
    ranges = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise ValueError("rate-card schedule hour range must be an object")
        start, end = _minutes(item.get("start")), _minutes(item.get("end"))
        if start == end:
            raise ValueError("rate-card schedule hour range is empty")
        ranges.append((start, end))
    return tuple(ranges)


def normalize_schedule(raw: Any) -> tuple[Mapping[str, Any], ...]:
    """Validate and freeze a schedule into the engine's internal form."""
    if isinstance(raw, Mapping) or not isinstance(raw, (list, tuple)):
        raise ValueError("rate-card schedule must be a list of windows")
    windows = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise ValueError("rate-card schedule window must be an object")
        identifier = item.get("id") or f"window-{index}"
        days = item.get("days", "all")
        rates = item.get("rates") or {}
        if not isinstance(identifier, str) or not identifier or len(identifier) > 4096:
            raise ValueError("rate-card schedule window id must be a non-empty bounded string")
        if days not in DAY_SCOPES:
            raise ValueError(f"rate-card schedule window days must be one of {DAY_SCOPES}")
        if not isinstance(rates, Mapping) or any(
            not isinstance(name, str) or not name for name in rates
        ):
            raise ValueError("rate-card schedule window rates must be keyed by dimension")
        windows.append(
            freeze(
                {
                    "id": identifier,
                    "days": days,
                    "hours": _ranges(item.get("hours")),
                    "rates": {key: decimal(value) for key, value in rates.items()},
                }
            )
        )
    return tuple(windows)


def _covers_day(days: str, moment: datetime) -> bool:
    return days == "all" or (days == "weekend") == (moment.weekday() >= 5)


def _covers_time(hours: tuple[tuple[int, int], ...], minute: int) -> bool:
    for start, end in hours:
        # start > end wraps past midnight ("22:00"-"02:00"), which is two spans
        # of the clock rather than an inverted one.
        if (start <= minute < end) if start <= end else (minute >= start or minute < end):
            return True
    return False


def window_rates(
    schedule: tuple[Mapping[str, Any], ...], moment: datetime | None
) -> tuple[str | None, Mapping[str, Decimal]]:
    """The first window covering *moment*; ``(None, {})`` means base rates."""
    if not schedule or moment is None:
        return None, {}
    utc = moment.astimezone(UTC) if moment.tzinfo is not None else moment.replace(tzinfo=UTC)
    minute = utc.hour * 60 + utc.minute
    for window in schedule:
        if _covers_day(str(window["days"]), utc) and _covers_time(window["hours"], minute):
            return str(window["id"]), window["rates"]
    return None, {}


def _clock(minutes: int) -> str:
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def schedule_to_json(schedule: tuple[Mapping[str, Any], ...]) -> list[dict[str, Any]]:
    return [
        {
            "id": window["id"],
            "days": window["days"],
            "hours": [
                {"start": _clock(start), "end": _clock(end)} for start, end in window["hours"]
            ],
            "rates": {key: str(value) for key, value in sorted(window["rates"].items())},
        }
        for window in schedule
    ]
