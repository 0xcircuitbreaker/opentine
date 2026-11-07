"""``tine task add|claim|heartbeat|done|list``: ``opentine-coord/1`` tasks and leases.

``add ID [--title T]`` creates ``coord/tasks/ID``; ``claim ID --holder NAME
[--ttl S]`` takes its lease by compare-and-swap and prints the fencing token;
``heartbeat ID --holder NAME --fencing N [--ttl S]`` extends it; ``done ID
--holder NAME --fencing N`` closes it; ``list`` shows every task. A refused
operation (held, stale, done, ...) exits 1 with ``{"error": {"code": ...}}``
under ``--json``. See :mod:`opentine.coord._tasks`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

ACTIONS = ("add", "claim", "heartbeat", "done", "list")


def add_task_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("task", help="Coordination tasks and leases (opentine-coord/1)")
    parser.add_argument("action", choices=ACTIONS)
    parser.add_argument("task", nargs="?", help="Task id (lowercase [a-z0-9._-])")
    parser.add_argument("--repo", default=".", metavar="PATH", help="v3 repository")
    parser.add_argument("--title", default="", help="add: a description")
    parser.add_argument("--holder", help="claim/heartbeat/done: who holds the lease")
    parser.add_argument("--fencing", type=int, help="heartbeat/done: the token claim printed")
    parser.add_argument("--ttl", type=float, default=60.0, help="Lease seconds (default 60)")
    parser.add_argument("--json", action="store_true", help="Machine-readable output")


def _run(args: argparse.Namespace) -> dict | list:
    from opentine.coord import _tasks
    from opentine.repo import Repo

    repo = Repo.open(args.repo)
    if args.action == "list":
        return _tasks.list_tasks(repo)
    if not args.task:
        raise ValueError(f"{args.action} needs a task id")
    if args.action == "add":
        return _tasks.add(repo, args.task, args.title)
    if not args.holder:
        raise ValueError(f"{args.action} needs --holder")
    if args.action == "claim":
        return _tasks.claim(repo, args.task, args.holder, args.ttl)
    if args.fencing is None:
        raise ValueError(f"{args.action} needs --fencing (the token claim printed)")
    if args.action == "heartbeat":
        return _tasks.heartbeat(repo, args.task, args.holder, args.fencing, args.ttl)
    return _tasks.done(repo, args.task, args.holder, args.fencing)


def _line(row: dict) -> str:
    holder = f" holder={row['holder']} fencing={row['fencing']}" if row["holder"] else ""
    lease = f" expires_ms={row['lease_expires_ms']}" if row["lease_expires_ms"] else ""
    return _terminal(f"{row['task']:<24} {row['status']:<8}{holder}{lease}  {row['title']}")


def cmd_task(args: argparse.Namespace) -> None:
    from opentine.coord._tasks import LeaseError

    try:
        result = _run(args)
    except LeaseError as exc:
        if args.json:
            body = {"error": {"code": exc.code, "message": str(exc)}, "command": "task"}
            sys.stdout.write(json.dumps(body) + "\n")
            raise SystemExit(1) from exc
        raise error(exc, prefix="task: ") from exc
    except (OSError, ValueError) as exc:
        raise error(exc, prefix="task: ") from exc
    if args.json:
        key = "tasks" if args.action == "list" else "task"
        sys.stdout.write(json.dumps({"command": f"task {args.action}", key: result}) + "\n")
        return
    for row in result if isinstance(result, list) else [result]:
        console.print(_line(row), markup=False)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"task": cmd_task}

__all__ = ["COMMANDS", "add_task_parser", "cmd_task"]
