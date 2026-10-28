"""Running a trusted fleet on the F3 parallel executor; its on-disk state.

Each member is one copy of one agent: key ``0..N-1``, argv exactly as declared,
the allowlisted environment only (``DEFAULT_ENV`` + the names the manifest
lists) plus ``OPENTINE_FLEET_ID``/``_MEMBER``/``_ROLE`` and the cost file
``tine run`` reports into. In the supervisor layout the supervisor is queued
first and every worker gets ``OPENTINE_FLEET_PARENT`` (the supervisor's name)
and, when the manifest declares one, ``OPENTINE_AGENT_PARENT`` (its agt_ ref)
-- the parent link ``tine run --harness`` records in the worker's identity.

State is the fan-out state format (``opentine-fanout-state/1``) under
``<manifest dir>/.tine_fleet/<id>.json`` with the manifest's digest as the
command digest. ``tine fleet stop ID`` drops ``<id>.stop`` beside it; the
running ``up`` polls for it and stops the executor, which kills every member's
whole process tree (process groups on POSIX, kill-on-close Job Objects on
Windows) and starts nothing more.
"""

from __future__ import annotations

import os
import sys
import threading
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import IO

from opentine.budget import SharedLedger
from opentine.fleet._manifest import Fleet
from opentine.parallel._executor import FINISHED, Executor, Member
from opentine.parallel._matrix import member_env
from opentine.parallel._state import State, new_id

STATE_DIR = ".tine_fleet"


def state_dir(fleet_root: Path) -> Path:
    folder = fleet_root / STATE_DIR
    if folder.is_symlink():
        raise ValueError(f"{folder} is a symlink")
    return folder


def plan(fleet: Fleet) -> list[dict]:
    """Members in launch order: the supervisor first, then each agent's copies."""
    agents = sorted(fleet.agents, key=lambda agent: agent.role != "supervisor")
    rows = []
    for agent in agents:
        for _ in range(agent.count):
            rows.append({"agent": agent.name, "role": agent.role})
    return [
        {"key": str(i), "vary": row, "ref": None, "run": None, "status": "pending",
         "returncode": None, "cost": None}
        for i, row in enumerate(rows)
    ]  # fmt: skip


def create(fleet: Fleet) -> State:
    return State.create(
        state_dir(fleet.root),
        id=new_id(),
        budget=None if fleet.budget is None else str(fleet.budget),
        command_digest=fleet.digest,
        members=plan(fleet),
        source={"kind": "fleet", "name": fleet.name, "layout": fleet.layout},
    )


def _members(fleet: Fleet, state: State) -> list[Member]:
    by_name = {agent.name: agent for agent in fleet.agents}
    supervisor = next((a for a in fleet.agents if a.role == "supervisor"), None)
    members = []
    for entry in state.data["members"]:
        if entry["status"] in FINISHED:
            continue
        agent = by_name[entry["vary"]["agent"]]
        cost_file = state.cost_file(entry["key"])
        extra = {
            "OPENTINE_FLEET_ID": state.id,
            "OPENTINE_FLEET_MEMBER": f"{agent.name}-{entry['key']}",
            "OPENTINE_FLEET_ROLE": agent.role,
            "OPENTINE_FANOUT_COST_FILE": str(cost_file),
        }
        if supervisor is not None and agent.role == "worker":
            extra["OPENTINE_FLEET_PARENT"] = supervisor.name
            if supervisor.agent_ref:
                extra["OPENTINE_AGENT_PARENT"] = supervisor.agent_ref
        env = member_env([*fleet.env, *agent.env], extra)
        info = {"agent": agent.name, "role": agent.role}
        log = state.directory / state.id / f"{entry['key']}.log"
        members.append(Member(entry["key"], list(agent.argv), env, agent.cwd, cost_file, log, info))
    return members


def stop_file(directory: Path, fleet_id: str) -> Path:
    return directory / f"{fleet_id}.stop"


def run(fleet: Fleet, state: State, out: IO[str] | None = None, poll: float = 0.2) -> int:
    """Run every unfinished member; 0 when all of them finished ``ok``."""
    out = out or sys.stdout
    ledger = SharedLedger(fleet.budget)
    members = _members(fleet, state)
    halt = stop_file(state.directory, state.id)
    halt.unlink(missing_ok=True)

    def on_event(event: dict) -> None:
        if event["event"] == "exit":
            fields = {k: event[k] for k in ("status", "returncode", "cost")}
            state.update(event["member"], ledger.spent(), **fields)
            out.write(f"[{event['member']}] {event.get('agent')} {event['status']}\n")
        elif event["event"] == "skipped":
            state.update(event["member"], ledger.spent(), status="skipped")
        elif event["event"] == "start":
            out.write(f"[{event['member']}] {event.get('agent')} started\n")
        out.flush()

    jobs = fleet.jobs or max(1, len(members))
    executor = Executor(members, jobs=jobs, timeout=fleet.timeout, ledger=ledger,
                        on_event=on_event)  # fmt: skip
    done = threading.Event()

    def watch() -> None:
        while not done.wait(poll):
            if os.path.lexists(halt):
                executor.stop()
                return

    watcher = threading.Thread(target=watch, name="tine-fleet-stop", daemon=True)
    watcher.start()
    try:
        executor.run()
    finally:
        done.set()
        watcher.join()
    return 0 if all(m["status"] == "ok" for m in state.data["members"]) else 1


def request_stop(directory: Path, fleet_id: str) -> Path:
    State.load(directory, fleet_id)  # a known fleet id only
    path = stop_file(directory, fleet_id)
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    os.close(os.open(path, flags, 0o600))
    return path


def cost(state: State) -> tuple[Decimal, int]:
    """``(total, members whose cost is unknown)`` from the recorded member costs."""
    total, unknown = Decimal(0), 0
    for member in state.data["members"]:
        try:
            value = Decimal(member["cost"]) if member["cost"] is not None else None
        except (InvalidOperation, TypeError):
            value = None
        if value is None or not value.is_finite() or value < 0:
            unknown += 1
        else:
            total += value
    return total, unknown


__all__ = ["STATE_DIR", "cost", "create", "plan", "request_stop", "run", "state_dir"]
