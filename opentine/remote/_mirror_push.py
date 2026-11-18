"""Mirror sync -> review runner: each moved ref becomes one ``mirror-sync`` push.

A successful sync compares the refs it found with the refs the previous state
held and spools one trigger per created, moved or deleted ref under the
tenant's mirror directory (``pushes/<digest>.json``). Each spooled file is
exactly what ``tine review runner --event`` takes, and is checked with the
runner's own ``check_trigger`` before it is written. Unlinking the mirror
deletes the spool with everything else.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from opentine._review_runner import check_trigger


def pushes(before: dict[str, Any] | None, after: dict[str, Any]) -> list[dict[str, Any]]:
    """The pushes between two mirror states, sorted by ref; none unless *after* synced."""
    if after.get("status") != "synced":
        return []
    old = dict((before or {}).get("refs") or {})
    new = dict(after.get("refs") or {})
    out = []
    for name in sorted(set(old) | set(new)):
        if old.get(name) == new.get(name):
            continue
        event: dict[str, Any] = {"source": "mirror-sync", "ref": name.removeprefix("refs/"),
                                 "at": after["synced_at"]}  # fmt: skip
        if name in old:
            event["before"] = old[name]
        if name in new:
            event["after"] = new[name]
        out.append(check_trigger(event))
    return out


def spool(place: Path, events: list[dict[str, Any]]) -> list[Path]:
    """Write each push to ``place/pushes``; the file name is its content digest."""
    written = []
    for event in events:
        raw = json.dumps(event, sort_keys=True).encode()
        target = place / "pushes" / f"{hashlib.sha256(raw).hexdigest()[:32]}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_suffix(".tmp")
        temp.write_bytes(raw)
        temp.replace(target)
        written.append(target)
    return written


def pending(place: Path) -> list[Path]:
    """The spooled pushes not yet handed to a runner, oldest first."""
    folder = place / "pushes"
    if not folder.is_dir():
        return []
    return sorted(folder.glob("*.json"), key=lambda p: (p.stat().st_mtime_ns, p.name))
