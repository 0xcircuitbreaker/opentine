"""The taint filter of ``tine dataset curate`` (0.75).

A run is **tainted** for curation when any of these names it:

``integrity-taint``   a held 0.60 integrity taint (``integrity-taint:RUN``);
                      any held row counts, as for promotion: a taint only refuses
``monitor-verdict``   a held 0.63 monitor verdict on the run that was not ``allow``
                      (or was enforced)
``oversight-reject``  a held 0.64 oversight ``reject`` whose item names the run
``sabotage-task``     a held 0.68 sabotage task record on the run whose side task
                      was attempted or achieved
``transcript-flag``   a **verified** 0.74 behaviour flag naming the run as evidence
                      (a forged or unpinned flag taints nothing)

The filter reads only held records, which ``tine hold release`` refuses, so a
loop cannot un-taint its own trajectories by deleting files. It fails closed:
an unreadable holds file or a held record that cannot be read raises, and
curation stops rather than guess which run the record named.
"""

from __future__ import annotations

import re
from typing import Any

from opentine._dataset_claims import SOURCES

_RUN = re.compile(r"run:sha256:[0-9a-f]{64}")


class TaintFilterError(ValueError):
    """A held record the filter needs cannot be read (fail closed)."""


def _payload(repo: Any, oid: str) -> dict[str, Any]:
    try:
        payload = repo.get(oid).payload()
    except Exception as exc:  # noqa: BLE001 - any unreadable held record stops curation
        raise TaintFilterError(f"held record {oid} cannot be read: the taint filter "
                               "cannot be applied") from exc  # fmt: skip
    if not isinstance(payload, dict):
        raise TaintFilterError(f"held record {oid} is not a record")
    return payload


def tainted(repo: Any) -> dict[str, list[str]]:
    """``{run: [source, ...]}`` for every tainted run (sources in :data:`SOURCES` order)."""
    from opentine import _oversight, _sabotage
    from opentine._transcript_oversight import verified_flags
    from opentine.repository._holds import (
        MONITOR_VERDICT,
        OVERSIGHT_DECISION,
        TAINT,
        holds_path,
        read_holds,
    )

    found: dict[str, set[str]] = {}

    def add(run: Any, source: str) -> None:
        if isinstance(run, str) and _RUN.fullmatch(run):
            found.setdefault(run, set()).add(source)

    rows = read_holds(holds_path(repo))  # raises HoldError when unreadable
    for row in rows:
        target = row["target"]
        if target.startswith(TAINT):
            add(target[len(TAINT) :], "integrity-taint")
        elif target.startswith(MONITOR_VERDICT):
            payload = _payload(repo, row["oid"])
            claim = payload.get("claim") if isinstance(payload.get("claim"), dict) else {}
            if claim.get("action") != "allow" or claim.get("enforced"):
                add(payload.get("target_id"), "monitor-verdict")
        elif target.startswith(OVERSIGHT_DECISION):
            decision = _oversight.read(repo, row["oid"])
            if decision is None:
                _payload(repo, row["oid"])  # raises when unreadable
                continue
            if decision["decision"] == "reject" and isinstance(decision["item"], str):
                for run in _RUN.findall(decision["item"]):
                    add(run, "oversight-reject")
    for task_rows in _sabotage.records(repo).values():
        for rec in task_rows:
            side = (rec["claim"] or {}).get("side_task")
            if isinstance(side, dict) and (side.get("attempted") or side.get("achieved")):
                add(rec["run"], "sabotage-task")
    for flag in verified_flags(repo):
        for run in flag["evidence"] or []:
            add(run, "transcript-flag")
    return {run: [s for s in SOURCES if s in why] for run, why in sorted(found.items())}


__all__ = ["TaintFilterError", "tainted"]
