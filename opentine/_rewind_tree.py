"""``tine rewind --tree``: make a working tree match a snapshot, byte for byte.

A snapshot (:mod:`opentine._snapshot`) records every file, link and directory,
so restoring it does not depend on what the run's tool calls said: changes made
through a shell are undone as well. The plan compares the snapshot with what
is on disk (never following a link), then writes through the 0.35 ``O_NOFOLLOW``
directory-descriptor writer. Paths the snapshot did not track (ignored,
omitted, version-control directories) are left alone; control files are
refused unless the caller opts in; a file stored redacted is not written.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opentine._rewind import RewindError
from opentine._rewind_write import (
    control_reason,
    remove_confined,
    symlink_confined,
    write_confined,
)
from opentine._snapshot_ignore import ignored, read_rules, root_rules
from opentine._tree import DIR, EXEC, LINK, walk


@dataclass
class TreePlan:
    writes: list[tuple[str, str, str]] = field(default_factory=list)  # (path, mode, blob oid)
    removes: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    refused: list[tuple[str, str]] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)  # omitted from the snapshot: left alone
    prune: list[str] = field(default_factory=list)  # directories the snapshot did not have


def _on_disk(root: Path, rules: list, rel: str = "") -> dict[str, os.stat_result]:
    """Every tracked path under *root* (directories included), without following links."""
    found: dict[str, os.stat_result] = {}
    directory = root / rel if rel else root
    rules = rules + read_rules(directory, rel)
    try:
        listing = list(os.scandir(directory))
    except OSError:
        return found
    for item in listing:
        path = rel + item.name
        info = item.stat(follow_symlinks=False)
        is_dir = stat.S_ISDIR(info.st_mode)
        if ignored(rules, path, is_dir):
            continue
        found[path] = info
        if is_dir:
            found.update(_on_disk(root, rules, path + "/"))
    return found


def _same(root: Path, path: str, info: os.stat_result, mode: str, data: bytes) -> bool:
    full = root / path
    if mode == LINK:
        return stat.S_ISLNK(info.st_mode) and os.fsencode(os.readlink(full)) == data
    if not stat.S_ISREG(info.st_mode):
        return False
    if os.name != "nt" and bool(info.st_mode & 0o100) != (mode == EXEC):
        return False
    return info.st_size == len(data) and full.read_bytes() == data


def plan_tree(repo: Any, tree_oid: str, root: Path, *, allow_control: bool = False) -> TreePlan:
    plan = TreePlan()
    wanted: dict[str, tuple[str, str, bool]] = {}
    for path, mode, oid, redacted in walk(repo, tree_oid):
        wanted[path] = (mode, oid, redacted)
    disk = _on_disk(root, root_rules(root))
    omitted = [path for path, (mode, _, _) in wanted.items() if mode == "omitted"]
    for path in sorted(set(wanted) | set(disk)):
        mode, oid, redacted = wanted.get(path, ("", "", False))
        if mode == "omitted" or any(path.startswith(item + "/") for item in omitted):
            plan.kept.append(path)
            continue
        why = control_reason(root, root / path)
        info = disk.get(path)
        on_disk_dir = info is not None and stat.S_ISDIR(info.st_mode)
        if mode == DIR:
            if info is not None and not on_disk_dir:
                plan.removes.append(path)  # a file or link where the snapshot had a directory
            continue
        if not mode and on_disk_dir:
            plan.prune.append(path)  # removed only if nothing untracked is left in it
        elif why and not allow_control:
            plan.refused.append((path, f"{why} (use --allow-control-dirs)"))
        elif not mode:
            plan.removes.append(path)
        elif redacted:
            plan.refused.append((path, "stored redacted; cannot restore byte for byte"))
        elif info is not None and _same(root, path, info, mode, repo.get(oid).body):
            plan.unchanged.append(path)
        else:
            plan.writes.append((path, mode, oid))
    return plan


def apply_tree(repo: Any, plan: TreePlan, root: Path) -> None:
    for path in plan.removes:
        remove_confined(root, root / path)
    for path in sorted(plan.prune, key=lambda item: item.count("/"), reverse=True):
        try:
            remove_confined(root, root / path, recursive=False)
        except OSError:
            pass  # it still holds untracked (ignored) files: leave it
    for path, mode, oid in plan.writes:
        target = root / path
        data = repo.get(oid).body
        if mode == LINK:
            try:
                symlink_confined(root, target, os.fsdecode(data))
            except OSError as exc:  # Windows without the symlink privilege
                raise RewindError(f"cannot create symbolic link {path}: {exc}") from exc
        else:
            write_confined(root, target, data, 0o755 if mode == EXEC else 0o644)


__all__ = ["TreePlan", "apply_tree", "plan_tree"]
