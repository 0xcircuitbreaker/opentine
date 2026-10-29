"""Removing finished fan-out state (``.tine/fanouts/<id>.json`` and ``<id>/``).

``tine fanout`` keeps a resumable record per fan-out plus a folder of member
cost files, and nothing ever removed them. ``gc`` now drops the state of a
fan-out whose every member finished (``ok`` or ``failed``) once its record has
not changed for :data:`GRACE` seconds. Anything unfinished, malformed, a
symlink or still young is left alone: ``--resume`` may still need it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from pathlib import Path

from opentine.repository import _winretry
from opentine.repository._paths import internal_path

#: Seconds a finished fan-out's record is kept after its last update.
GRACE = 7 * 86400.0
_ID = re.compile(r"^[0-9a-f]{12}$")
_FINISHED = {"ok", "failed"}
_MAX_BYTES = 16 * 1024 * 1024


def _finished(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(_MAX_BYTES + 1)
        data = json.loads(raw) if len(raw) <= _MAX_BYTES else None
    except (OSError, ValueError):
        return False
    members = data.get("members") if isinstance(data, dict) else None
    if not isinstance(members, list):
        return False
    return all(isinstance(m, dict) and m.get("status") in _FINISHED for m in members)


def tidy_fanouts(root: Path, grace: float = GRACE) -> int:
    """Remove finished fan-out state older than *grace*; the number removed."""
    directory = internal_path(root, "fanouts")
    try:
        names = sorted(os.listdir(directory))
    except (FileNotFoundError, NotADirectoryError):
        return 0
    cutoff = time.time() - grace
    removed = 0
    for name in names:
        fanout_id = name.removesuffix(".json")
        record = directory / name
        if fanout_id == name or not _ID.fullmatch(fanout_id) or record.is_symlink():
            continue
        try:
            if record.stat().st_mtime > cutoff or not _finished(record):
                continue
        except OSError:
            continue
        folder = directory / fanout_id
        try:
            if folder.is_symlink():
                folder.unlink()
            elif folder.is_dir():
                shutil.rmtree(folder)
            _winretry.unlink(record)  # the record last: a crash leaves it to retry
        except OSError:
            continue
        removed += 1
    return removed
