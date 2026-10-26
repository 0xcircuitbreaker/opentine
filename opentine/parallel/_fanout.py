"""Forks from one fork point, their refs, the fan-out record, and driving members.

* The fork point's causal closure is walked **once** for all N forks
  (:func:`~opentine.repository._fork_state.fork_closure`), not once per fork.
* Every member ref (``experiments/fanout/<id>/<n>``) is written by one
  :meth:`Repo.update_refs` transaction: all of them exist, or none do.
* The record is an annotation on the source run (``opentine.fanout.<id>`` in its
  metadata) -- no new object type, so every reader since 0.3 still opens it.
"""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal, InvalidOperation
from pathlib import Path

from opentine.budget import SharedLedger
from opentine.parallel._executor import FINISHED, Executor, Member
from opentine.parallel._matrix import member_env, render, vary_env
from opentine.parallel._state import State
from opentine.repository._fork_state import fork_closure, fork_payload

RECORD_FORMAT = "opentine-fanout/1"
_FORK_KEYS = ("model", "prompt")


def prepare_forks(repo, source: str, from_event: str, matrix: list[dict], fid: str) -> list[dict]:
    payload = repo.get(source).payload()
    if from_event not in payload.get("events", []):
        raise ValueError("fork event does not belong to the source run")
    closure = fork_closure(repo, source, from_event)  # one walk for every member
    members, updates = [], []
    for index, values in enumerate(matrix):
        overrides = {"resume": True, **{k: values[k] for k in _FORK_KEYS if k in values}}
        forked = fork_payload(repo, source, payload, from_event, overrides, closure=closure)
        run = repo.put("run", forked)
        ref = f"experiments/fanout/{fid}/{index}"
        updates.append((ref, run, None))
        members.append(
            {
                "cost": None,
                "key": str(index),
                "ref": ref,
                "returncode": None,
                "run": run,
                "status": "pending",
                "vary": values,
            }
        )
    repo.update_refs(updates, actor="fan-out")
    return members


def record(repo, source: str, fid: str, from_event: str, members: list[dict], limits: dict) -> None:
    from opentine.repository._annotations import load_run_annotation, write_run_annotation

    metadata, tags = load_run_annotation(repo, source)
    metadata[f"opentine.fanout.{fid}"] = {
        "format": RECORD_FORMAT,
        "fork_event": from_event,
        "members": [{"key": m["key"], "ref": m["ref"], "run": m["run"]} for m in members],
        **limits,
    }
    write_run_annotation(repo, source, metadata, tags)


def _prior_spend(state: State) -> str:
    try:
        total = sum((Decimal(value) for value in state.data["spent"].values()), Decimal(0))
    except (InvalidOperation, TypeError):
        return "NaN"  # an unreadable ledger closes the budget (fail closed)
    return str(total)


def drive(
    state: State,
    template: list[str],
    *,
    jobs: int,
    timeout: float | None,
    allow_env: list[str],
    reporter: Callable[[dict], None],
    log_dir: Path | None = None,
    cwd_for: Callable[[dict], str | None] = lambda member: None,
) -> int:
    """Run every unfinished member; return 0 when all of them finished ``ok``."""
    budget = state.data["budget"]
    ledger = SharedLedger(None if budget is None else float(budget))
    if state.data["spent"]:
        ledger.report("resumed", _prior_spend(state))
    fid = state.id
    members = []
    for entry in state.data["members"]:
        if entry["status"] in FINISHED:
            continue
        key = entry["key"]
        values = {
            **entry["vary"],
            "index": key,
            "fanout": fid,
            "ref": entry["ref"] or "",
            "run": entry["run"] or "",
        }
        cost_file = state.cost_file(key)
        extra = {
            **vary_env(entry["vary"]),
            "OPENTINE_FANOUT_ID": fid,
            "OPENTINE_FANOUT_INDEX": key,
            "OPENTINE_FANOUT_COST_FILE": str(cost_file),
        }
        if entry["run"]:
            extra.update(OPENTINE_FANOUT_RUN=entry["run"], OPENTINE_FANOUT_REF=entry["ref"])
        members.append(
            Member(
                key,
                render(template, values),
                member_env(allow_env, extra),
                cwd_for(entry),
                cost_file,
                (log_dir / f"{fid}-{key}.log") if log_dir else None,
                {k: entry[k] for k in ("ref", "run") if entry[k]},
            )
        )

    def on_event(event: dict) -> None:
        reporter(event)
        if event["event"] == "exit":
            fields = {k: event[k] for k in ("status", "returncode", "cost")}
            state.update(event["member"], ledger.spent(), **fields)
        elif event["event"] == "skipped":
            state.update(event["member"], ledger.spent(), status="skipped")

    executor = Executor(members, jobs=jobs, timeout=timeout, ledger=ledger, on_event=on_event)
    try:
        executor.run()
    finally:
        counts: dict[str, int] = {}
        for entry in state.data["members"]:
            counts[entry["status"]] = counts.get(entry["status"], 0) + 1
        reporter(
            {"event": "summary", "counts": counts, "spent": str(ledger.total()), "budget": budget}
        )
    return 0 if all(m["status"] == "ok" for m in state.data["members"]) else 1


__all__ = ["RECORD_FORMAT", "drive", "prepare_forks", "record"]
