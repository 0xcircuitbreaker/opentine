"""Reflog expiry: drop old ref history so ``tine prune`` can reclaim what only it named.

Conservative by default: a row goes only when it is older than
:data:`DEFAULT_EXPIRE_DAYS` *and* is not among the newest :data:`DEFAULT_KEEP`
rows of its ref, and a row recording the ref's current target is always kept.
Tag reflogs never expire. The repository's ``config.json`` may set
``"reflog": {"expire_days": N, "keep": N}`` (``"expire_days": null`` = never);
0.12 ignores the key. Each log is rewritten under its ref's own lock, the same
lock a ref update appends under, so no concurrent row is lost; a ref that is
locked right now is skipped.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from opentine.repository._config import read_config
from opentine.repository._lockfile import acquire
from opentine.repository._paths import atomic_bytes, internal_files, internal_path
from opentine.repository._ref_store import read_ref_oid

DEFAULT_EXPIRE_DAYS = 90.0
DEFAULT_KEEP = 100


def policy(root: Path) -> tuple[float | None, int]:
    """(expire days or ``None`` for never, rows always kept) from the descriptor."""
    try:
        setting = read_config(internal_path(root, "config.json")).get("reflog")
    except (OSError, ValueError):
        setting = None
    days: float | None = DEFAULT_EXPIRE_DAYS
    keep = DEFAULT_KEEP
    if isinstance(setting, dict):
        value = setting.get("expire_days", days)
        if value is None:
            days = None
        elif isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
            days = float(value)
        count = setting.get("keep", keep)
        if type(count) is int and count >= 0:
            keep = count
    return days, keep


def _kept(lines: list[bytes], cutoff_ns: int, keep: int, current: str | None) -> list[bytes]:
    survivors: list[bytes] = []
    newest_first = list(reversed(lines))
    for index, line in enumerate(newest_first):
        try:
            row = json.loads(line)
            stamp = int(row.get("time_ns"))
            target = row.get("new")
        except (ValueError, TypeError, AttributeError):
            survivors.append(line)  # not ours to judge: keep what cannot be read
            continue
        if index < keep or stamp >= cutoff_ns or (current is not None and target == current):
            survivors.append(line)
    return list(reversed(survivors))


def expire_reflogs(
    root: Path, days: float | None = None, keep: int | None = None, *, dry_run: bool = False
) -> int:
    """Drop expired reflog rows; return how many were (or would be) dropped."""
    configured_days, configured_keep = policy(root)
    days = configured_days if days is None else days
    keep = configured_keep if keep is None else keep
    if days is None:
        return 0
    cutoff_ns = time.time_ns() - int(days * 86400 * 1e9)
    logs = internal_path(root, "logs")
    dropped = 0
    for path in sorted(internal_files(root, "logs")):
        name = path.relative_to(logs).as_posix()
        if name.startswith("tags/") or path.name.endswith(".lock"):
            continue
        dropped += _expire_one(root, name, path, cutoff_ns, keep, dry_run)
    return dropped


def _expire_one(root: Path, name: str, path: Path, cutoff_ns: int, keep: int, dry: bool) -> int:
    ref_path = internal_path(root, "refs", *Path(name).parts)
    lock_path = ref_path.with_name(ref_path.name + ".lock")
    held = False
    try:
        if not dry:
            if not ref_path.parent.is_dir():
                ref_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.close(acquire(lock_path))
            held = True
        lines = [line for line in path.read_bytes().splitlines() if line.strip()]
        current = read_ref_oid(root, name) if ref_path.is_file() else None
        kept = _kept(lines, cutoff_ns, keep, current)
        if not dry and len(kept) != len(lines):
            atomic_bytes(path, b"".join(line + b"\n" for line in kept))
        return len(lines) - len(kept)
    except (FileExistsError, FileNotFoundError):
        return 0  # a writer holds the ref right now, or the log vanished
    except (OSError, ValueError):
        return 0
    finally:
        if held:
            lock_path.unlink(missing_ok=True)
