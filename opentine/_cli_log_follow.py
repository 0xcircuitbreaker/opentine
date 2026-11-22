"""``tine log -f [RUN|--all] [--json]``: follow run events as they become durable.

The text form prints one line per event with its verification status;
``--json`` prints one ``tine-cli-log-follow/1`` JSON Lines record per row
(docs/LIVE.md). ``--lines N`` shows the last N events of each followed run
first; ``--max-events N`` stops after N rows (scripts, tests); Ctrl-C stops.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from collections.abc import Callable
from typing import Any

from opentine._cli_common import _terminal
from opentine._repo_cli_render import _short_oid
from opentine._tail import RUN_SPACES, Follower
from opentine.repo import Repo

SCHEMA = "tine-cli-log-follow/1"
DEFAULT_INTERVAL = 0.2
MAX_INTERVAL = 60.0
_LABEL = {"verified": "verified", "unverified": "UNVERIFIED", "invalid": "INVALID"}


def ref_name(value: str | None) -> str:
    name = value or "heads/main"
    return name if name.startswith(RUN_SPACES) else f"heads/{name}"


def text_line(item: dict[str, Any]) -> str:
    ref = _terminal(str(item["ref"]))
    if item["type"] == "rewrite":
        return f"-- {ref} was rewritten; following its new tip"
    kind = _terminal(str(item["kind"] or "?"))
    label = _LABEL.get(str(item["status"]), "UNVERIFIED")
    return f"{_short_oid(item['event_id'])} {ref} #{item['index']} {kind} [{label}]"


def follow(
    args: argparse.Namespace,
    console,
    *,
    wait: Callable[[float], Any] | None = None,
    write: Callable[[str], None] | None = None,
) -> int:
    """Follow until ``--max-events`` rows were shown (or forever); the number shown."""
    if getattr(args, "graph", False) or getattr(args, "oneline", False):
        raise ValueError("log -f follows events; it does not combine with --graph/--oneline")
    given = getattr(args, "interval", None)
    interval = DEFAULT_INTERVAL if given is None else float(given)
    if not 0 < interval <= MAX_INTERVAL:
        raise ValueError(f"--interval must be in (0, {MAX_INTERVAL:g}] seconds")
    lines = getattr(args, "lines", None)
    if lines is not None and lines < 0:
        raise ValueError("--lines must be 0 or more")
    limit = getattr(args, "max_events", None)
    if limit is not None and limit < 1:
        raise ValueError("--max-events must be 1 or more")
    repo = Repo.open(args.repo)
    names = None if args.all else [ref_name(args.ref)]
    follower = Follower(repo, repo.list_refs, names=names, backlog=10 if lines is None else lines)
    as_json = bool(getattr(args, "json", False))
    pause = wait or threading.Event().wait
    out = write or _stdout
    shown = 0
    try:
        while limit is None or shown < limit:
            budget = 1000 if limit is None else min(1000, limit - shown)
            rows = follower.poll(budget)
            for item in rows:
                if as_json:
                    record = {"command": "log", "schema": SCHEMA, "row": item}
                    out(json.dumps(record, sort_keys=True, separators=(",", ":")))
                else:
                    out(text_line(item))
                shown += 1
            if not rows:
                pause(interval)
    except KeyboardInterrupt:
        pass
    return shown


def _stdout(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def add_follow_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-f", "--follow", action="store_true", help="Follow new events as they become durable"
    )
    parser.add_argument("--lines", "-n", type=int, default=None, help="With -f: show N first")
    parser.add_argument("--interval", type=float, default=None, help="With -f: poll seconds")
    parser.add_argument("--max-events", type=int, default=None, help="With -f: stop after N")


__all__ = ["SCHEMA", "add_follow_args", "follow", "ref_name", "text_line"]
