"""Folding ``spend`` ledger entries into totals (0.69; reservations and judge spend 0.87).

A spend entry counts once per *key*: its ``run`` (and, for a proxied model call,
its ``call``). Entries with the same key keep the largest value of each unit, so
a run recorded twice still counts once. The ``tine record`` proxy writes two
entries per call: a ``phase: "reserve"`` entry (a pessimistic estimate, before
the call is forwarded) and a ``phase: "settle"`` entry (what the provider
reported). A settle entry replaces its reservation only when every entry under
that key is signed and the settle entry's signer wrote the reservation;
otherwise the largest value counts (fail safe: an entry can hide no spend).
Calls tagged ``judge`` or ``scorer`` also count toward ``judge_tokens`` and
``judge_money_usd``.
"""

from __future__ import annotations

import math
from typing import Any

UNITS = ("tokens", "input_tokens", "output_tokens", "money_usd", "gpu_hours", "egress_bytes")
JUDGE = ("judge_tokens", "judge_money_usd")
INTEGER = ("tokens", "input_tokens", "output_tokens", "egress_bytes", "judge_tokens")


def _number(value: Any) -> float:
    ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    return float(value) if ok and math.isfinite(value) and value >= 0 else 0.0


def _units(value: dict[str, Any]) -> dict[str, float]:
    cost = value.get("cost") if isinstance(value.get("cost"), dict) else {}
    got = {"tokens": cost.get("total_tokens"), "input_tokens": cost.get("input_tokens"),
           "output_tokens": cost.get("output_tokens"), "money_usd": cost.get("total_cost"),
           "gpu_hours": value.get("gpu_hours"),
           "egress_bytes": value.get("egress_bytes")}  # fmt: skip
    out = {unit: _number(got[unit]) for unit in UNITS}
    judge = value.get("role") in ("judge", "scorer")
    out["judge_tokens"] = out["tokens"] if judge else 0.0
    out["judge_money_usd"] = out["money_usd"] if judge else 0.0
    return out


def _max(a: dict[str, float] | None, b: dict[str, float]) -> dict[str, float]:
    return dict(b) if a is None else {u: max(a[u], b[u]) for u in a}


def fold(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Totals of every ``spend`` row in *rows* (ledger rows from ``_budget_ledger.read``)."""
    keys: dict[Any, dict[str, Any]] = {}
    runs = set()
    for row in rows:
        value = row["value"]
        if value.get("entry") != "spend":
            continue
        run = value.get("run") if isinstance(value.get("run"), str) else row["id"]
        call = value.get("call")
        call = call if isinstance(call, (int, str)) and not isinstance(call, bool) else None
        runs.add(run)
        slot = keys.setdefault((run, call), {"settle": None, "other": None, "reservers": set(),
                                              "settlers": set(), "clean": True})  # fmt: skip
        got = _units(value)
        phase = value.get("phase")
        if phase == "settle" and call is not None and row["signed"]:
            slot["settle"] = _max(slot["settle"], got)
            slot["settlers"].add(row["signer"])
            continue
        slot["other"] = _max(slot["other"], got)
        if phase == "reserve" and row["signed"]:
            slot["reservers"].add(row["signer"])
        else:
            slot["clean"] = False
    finals = []
    for slot in keys.values():
        trusted = (slot["settle"] is not None and slot["clean"] and len(slot["settlers"]) == 1
                   and slot["reservers"] <= slot["settlers"])  # fmt: skip
        if trusted:
            finals.append(slot["settle"])
        else:
            parts = [p for p in (slot["settle"], slot["other"]) if p is not None]
            finals.append(_max(parts[0], parts[-1]))
    totals: dict[str, Any] = {u: math.fsum(f[u] for f in finals) for u in (*UNITS, *JUDGE)}
    for unit in INTEGER:
        totals[unit] = int(totals[unit])
    totals["runs"] = len(runs)
    return totals


__all__ = ["JUDGE", "UNITS", "fold"]
