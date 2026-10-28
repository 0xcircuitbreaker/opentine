"""Status lines for a running fan-out: one NDJSON object per event with ``--json``.

Events carry ids, statuses, return codes, costs and timings -- never a member's
argv, environment or variation values, which may hold prompts or secrets.
"""

from __future__ import annotations

import json
import sys
from typing import IO

_SAFE = ("event", "fanout", "member", "status", "reason", "returncode", "cost", "seconds")
_SAFE_EXTRA = ("ref", "run", "pid", "members", "counts", "spent", "budget", "jobs")


class Reporter:
    def __init__(self, fanout: str, *, json_lines: bool, stream: IO[str] | None = None):
        self.fanout = fanout
        self.json_lines = json_lines
        self.stream = stream or sys.stdout

    def __call__(self, event: dict) -> None:
        event = {"fanout": self.fanout, **event}
        safe = {k: event[k] for k in (*_SAFE, *_SAFE_EXTRA) if k in event}
        if self.json_lines:
            self.stream.write(json.dumps(safe, sort_keys=True) + "\n")
        else:
            self.stream.write(_human(safe) + "\n")
        self.stream.flush()


def _human(event: dict) -> str:
    kind = event["event"]
    who = f"[{event.get('member', '-')}]"
    if kind == "start":
        return f"{who} started pid {event.get('pid')} {event.get('ref') or ''}".rstrip()
    if kind == "exit":
        cost = f" ${event['cost']}" if event.get("cost") is not None else ""
        code = event.get("returncode")
        return f"{who} {event['status']} (exit {code}, {event.get('seconds', 0)}s){cost}"
    if kind == "skipped":
        return f"{who} skipped ({event.get('reason')})"
    if kind == "summary":
        counts = ", ".join(f"{k} {v}" for k, v in sorted(event.get("counts", {}).items()))
        return f"fan-out {event['fanout']}: {counts}; spent ${event.get('spent', '0')}"
    if kind == "prepared":
        return f"fan-out {event['fanout']}: {event.get('members')} members prepared"
    return json.dumps(event, sort_keys=True)


__all__ = ["Reporter"]
