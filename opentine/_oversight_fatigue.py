"""Approver-fatigue metrics (0.64): ``tine oversight fatigue``. Advisory only.

Computed from the rebuilt queue (:mod:`opentine._oversight_queue`) and the
timestamps the records carry, never from when the command runs: time to
decision is a counted decision's ``decided_at`` minus its item's
``opened_at``. An approval is a **rubber stamp** when it records no viewed
evidence (``viewed`` is absent or names no evidence) or when ``decided_at`` is
less than ``min_review_seconds`` after ``viewed.at``. The age of a pending
item needs a "now", which the caller injects (``--now``, else the clock).

Per owner decision D12 the report is advisory: it has no ``fail:`` finding,
and the command exits 0 whatever the numbers are. Nothing reads it to gate.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

DEFAULT_MIN_REVIEW_SECONDS = 30


def parse_time(text: Any) -> datetime | None:
    if not isinstance(text, str):
        return None
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def _seconds(a: Any, b: Any) -> float | None:
    start, end = parse_time(a), parse_time(b)
    return None if start is None or end is None else (end - start).total_seconds()


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered, mid = sorted(values), len(values) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def _stamp(row: dict[str, Any], floor: int) -> bool:
    viewed = row.get("viewed")
    if not isinstance(viewed, dict) or not viewed.get("evidence"):
        return True
    gap = _seconds(viewed.get("at"), row.get("decided_at"))
    return gap is None or gap < floor


def report(body: dict[str, Any], *, now: Callable[[], datetime],
           min_review_seconds: int = DEFAULT_MIN_REVIEW_SECONDS) -> dict[str, Any]:  # fmt: skip
    """The advisory fatigue report for a rebuilt queue *body*."""
    per: dict[str, dict[str, Any]] = {}
    waits: list[float] = []
    stamps = approvals = 0
    for item in body["items"]:
        for row in item["decisions"]:
            if not row["counted"]:
                continue
            who = per.setdefault(row["signer"], {"signer": row["signer"], "approvals": 0,
                                                 "rejections": 0, "rubber_stamps": 0,
                                                 "_waits": []})  # fmt: skip
            wait = _seconds(item["opened_at"], row["decided_at"])
            if wait is not None:
                waits.append(wait)
                who["_waits"].append(wait)
            if row["decision"] == "reject":
                who["rejections"] += 1
                continue
            approvals += 1
            who["approvals"] += 1
            if _stamp(row, min_review_seconds):
                stamps += 1
                who["rubber_stamps"] += 1
    at = now().isoformat()
    ages = [_seconds(i["opened_at"], at) for i in body["items"] if i["state"] == "pending"]
    rows = []
    for signer in sorted(per):
        row = per[signer]
        row["median_seconds_to_decision"] = _median(row.pop("_waits"))
        rows.append(row)
    return {"advisory": True, "min_review_seconds": min_review_seconds, "queue": body["digest"],
            "decisions": sum(r["approvals"] + r["rejections"] for r in rows),
            "approvals": approvals, "rubber_stamps": stamps,
            "rubber_stamp_rate": stamps / approvals if approvals else None,
            "median_seconds_to_decision": _median(waits),
            "max_seconds_to_decision": max(waits) if waits else None,
            "pending": len(ages),
            "oldest_pending_seconds": max((a for a in ages if a is not None), default=None),
            "approvers": rows}  # fmt: skip


__all__ = ["DEFAULT_MIN_REVIEW_SECONDS", "parse_time", "report"]
