"""Loose-object housekeeping shared by gc, auto-pack and prune.

Loose objects live at ``objects/<kind>/<xx>/<62 hex>``. Packing used to leave
every emptied ``<xx>`` fan-out directory behind (725 of them, ~3 MB of ``du``,
in a 20-run repository). They are now removed with ``os.rmdir``, which only
ever removes an *empty* directory; a writer that raced the removal between
creating the directory and creating its temporary file retries in
:func:`opentine.repository._paths.atomic_bytes`.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from pathlib import Path

from opentine.kernel import OBJECT_TYPES
from opentine.repository._paths import internal_path

_HEX = frozenset("0123456789abcdef")


def _names(directory: Path) -> list[str]:
    try:
        with os.scandir(directory) as entries:
            return sorted(entry.name for entry in entries)
    except (FileNotFoundError, NotADirectoryError):
        return []


def fanout_dirs(root: Path) -> Iterator[Path]:
    """Every ``objects/<kind>/<xx>`` directory (never following links)."""
    objects = internal_path(root, "objects")
    for kind in _names(objects):
        if kind not in OBJECT_TYPES or (objects / kind).is_symlink():
            continue
        for prefix in _names(objects / kind):
            if len(prefix) == 2 and set(prefix) <= _HEX:
                path = objects / kind / prefix
                if path.is_dir() and not path.is_symlink():
                    yield path


def loose_entries(root: Path) -> Iterator[tuple[str, Path, os.stat_result]]:
    """(oid, path, lstat) for every well-formed loose object file."""
    for directory in fanout_dirs(root):
        kind, prefix = directory.parent.name, directory.name
        for name in _names(directory):
            if len(name) != 62 or not set(name) <= _HEX:
                continue
            path = directory / name
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue  # packed and removed meanwhile
            if os.path.isfile(path) and not os.path.islink(path):
                yield f"{kind}:sha256:{prefix}{name}", path, info


def old_loose(root: Path, min_age: float, *, limit: int | None = None) -> list[str]:
    """Loose oids last written (or freshened) at least *min_age* seconds ago."""
    cutoff = time.time() - min_age
    found: list[str] = []
    for oid, _, info in loose_entries(root):
        if info.st_mtime <= cutoff:
            found.append(oid)
            if limit is not None and len(found) >= limit:
                break
    return found


def remove_empty_dir(directory: Path) -> bool:
    """``rmdir`` *directory* if it is empty right now; never raise."""
    try:
        os.rmdir(directory)
    except OSError:  # not empty, already gone, or held open (Windows)
        return False
    return True


def sweep_empty_fanout(root: Path) -> int:
    """Remove every empty fan-out directory (older releases left them all)."""
    return sum(remove_empty_dir(directory) for directory in list(fanout_dirs(root)))
