"""Directory listings reused while a directory is provably unchanged.

Listing an object directory validates every entry (no symlink, no special or
hard-linked file, confined to the root). Doing that for every annotation on
every ``put_run`` made writing N runs cost O(N^2). A listing is reused only while
the directory's own ``lstat`` fingerprint -- type, inode, device, mtime, ctime --
is unchanged, so any entry added, removed, renamed over, or the directory being
swapped for a symlink or junction forces a full, validated rescan. Like git's
racy-index rule, a directory modified within the last few seconds is never
trusted from cache: a coarse filesystem clock (FAT keeps 2 s) could otherwise
hide a change made in the same tick. Every object actually read is still
validated by its own confined path on read.
"""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")

_RACY_SECONDS = 3.0
_MAX_ENTRIES = 65_536
_CACHE: dict[str, tuple[tuple[int, ...], Any]] = {}
#: Full (validated) rescans performed; tests read it to check scaling.
SCANS = [0]


def fingerprint(path: Path) -> tuple[int, ...] | None:
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        return None
    return (info.st_mode, info.st_ino, info.st_dev, info.st_mtime_ns, info.st_ctime_ns)


def cached(path: Path, scan: Callable[[], T]) -> T:
    """``scan()``'s result for *path*, reused while the directory is unchanged."""
    key = str(path)
    before = fingerprint(path)
    hit = _CACHE.get(key)
    if before is not None and hit is not None and hit[0] == before:
        return hit[1]
    SCANS[0] += 1
    result = scan()
    after = fingerprint(path)
    newest = max(before[3], before[4]) if before is not None else 0
    if before is not None and after == before and time.time_ns() - newest > _RACY_SECONDS * 1e9:
        if len(_CACHE) >= _MAX_ENTRIES:
            _CACHE.clear()
        _CACHE[key] = (before, result)
    else:
        _CACHE.pop(key, None)
    return result
