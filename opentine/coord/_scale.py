"""The task-claim scale harness (0.47 acceptance: 1,000 tasks x 50 workers).

:func:`run` adds *tasks* tasks, then starts *workers* threads that each walk
every task in their own shuffled order and try to claim it. A worker that wins
a claim either finishes it (``done`` with its fencing token) or, every
*crash_every*-th win, "crashes": it walks away holding a short lease, so the
task must be re-claimed after the lease runs out, and the crashed worker's late
``done`` (with its now-stale token) must be refused.

The report counts what the acceptance criterion asks for:

* ``lost``: tasks not ``done`` at the end (0 is required);
* ``duplicated``: tasks finished more than once, or two winning claims that got
  the same fencing token (0 is required);
* ``stale_accepted``: late ``done`` calls from crashed holders that were
  accepted (0 is required).

*make_tasks* returns an object with the :mod:`opentine.coord._tasks` call shape
(:class:`opentine._cli_task_remote.RemoteTasks`, or a local adapter); it is
called once per thread so each worker has its own connection.
"""

from __future__ import annotations

import random
import threading
import time
from collections import Counter
from collections.abc import Callable
from typing import Any

from opentine.coord._tasks import LeaseError

LEASE = 60.0
CRASH_LEASE = 0.2


def _worker(api: Any, name: str, ids: list[str], crash_every: int, seed: int, log: dict) -> None:
    order, wins, finished = list(ids), 0, log["finished"]
    random.Random(seed).shuffle(order)
    pending = set(order)
    while pending:
        for task in order:
            if task not in pending or task in finished:  # a hint only: the server decides
                pending.discard(task)
                continue
            crash = bool(crash_every) and (wins + 1) % crash_every == 0
            try:
                value = api.claim(task, name, CRASH_LEASE if crash else LEASE)
            except LeaseError as exc:
                if exc.code == "done":
                    finished.add(task)
                continue
            wins += 1
            with log["lock"]:
                log["claims"].append((task, value["fencing"]))
            if crash:
                log["crashed"].append((api, task, name, value["fencing"]))
                continue
            api.done(task, name, value["fencing"])  # a 60 s lease: a refusal here is a bug
            with log["lock"]:
                log["done"].append(task)
            finished.add(task)
            pending.discard(task)
        if pending:
            time.sleep(CRASH_LEASE / 4)


def run(
    make_tasks: Callable[[], Any], tasks: int, workers: int, *, crash_every: int = 0
) -> dict[str, Any]:
    """Run the scale test; the report (see the module docstring)."""
    setup = make_tasks()
    ids = [f"t{index:05d}" for index in range(tasks)]
    for task in ids:
        setup.add(task, f"scale task {task}")
    log: dict[str, Any] = {"lock": threading.Lock(), "claims": [], "done": [], "crashed": [],
                           "finished": set()}  # fmt: skip
    started = time.monotonic()
    threads = [
        threading.Thread(target=_worker, args=(make_tasks(), f"w{n}", ids, crash_every, n, log))
        for n in range(workers)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    stale_accepted = 0
    for api, task, name, fencing in log["crashed"]:
        try:
            api.done(task, name, fencing)
            stale_accepted += 1
        except LeaseError:
            pass
    finished = Counter(log["done"])
    tokens = Counter(log["claims"])
    final = {row["task"]: row for row in setup.list_tasks()}
    lost = sum(1 for task in ids if final.get(task, {}).get("status") != "done")
    duplicated = sum(1 for n in finished.values() if n > 1) + sum(
        1 for n in tokens.values() if n > 1
    )
    return {"tasks": tasks, "workers": workers, "claims": len(log["claims"]),
            "crashed": len(log["crashed"]), "done": len(log["done"]), "lost": lost,
            "duplicated": duplicated, "stale_accepted": stale_accepted,
            "seconds": round(time.monotonic() - started, 3)}  # fmt: skip


__all__ = ["run"]
