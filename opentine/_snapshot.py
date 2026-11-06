"""Per-turn workspace snapshots: ``snapshot(repo, root)`` -> a tree blob id.

Each call walks *root* without following any symbolic link (a link is
recorded as a ``120000`` entry holding its target), stores every file as a
content-addressed blob and every directory as a tree blob. Unchanged files and
directories hash to the oids of the previous turn, so a turn costs only what
changed. A :class:`StatCache` carried between turns skips re-reading files
whose size, mtime and inode are unchanged.

Ignored: version-control directories, ``.gitignore`` rules, ``.tineignore``
excludes and the caller's *ignore* patterns. Files over *max_file_bytes*,
unreadable files, ``.tineignore`` ``redact:`` paths and non-UTF-8 names are
listed in the tree's ``omitted`` list (by name, when it is UTF-8) and a restore
leaves them alone. Content that redaction would change is stored redacted and
marked ``redacted``: a restore refuses it rather than write the scrubbed text.

Callers (the ``tine hook`` protocol) link the result from a step's event with
:func:`opentine._tree.link_tree`.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opentine._snapshot_ignore import ignored, read_rules, root_rules
from opentine._tree import DIR, EXEC, FILE, LINK, link_tree, put_tree

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_FILES = 200_000

StatCache = dict[str, tuple[tuple[int, int, int, int], str, bool]]


@dataclass
class Snapshot:
    oid: str
    files: int = 0
    bytes_read: int = 0  # file bytes hashed this turn (cache misses)
    omitted: list[tuple[str, str]] = field(default_factory=list)
    cache: StatCache = field(default_factory=dict)


class SnapshotError(ValueError):
    pass


def _store_file(repo: Any, data: bytes) -> tuple[str, bool]:
    from opentine.redaction import redact_blob

    scrubbed = redact_blob(data)
    return repo.put("blob", scrubbed, redact=False), scrubbed != data


def _key(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_size, info.st_mtime_ns, info.st_ino, info.st_mode)


class _Walker:
    def __init__(self, repo: Any, root: Path, rules: list, limit: int, cache: StatCache):
        self.repo, self.root, self.limit = repo, root, limit
        self.rules, self.old, self.result = rules, cache, Snapshot("")
        self.redact = _redact_globs(root)

    def tree(self, directory: Path, rel: str, rules: list) -> str:
        rules = rules + read_rules(directory, rel)
        entries: list[dict[str, Any]] = []
        omitted: list[dict[str, str]] = []
        try:
            listing = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise SnapshotError(f"cannot list {directory}: {exc}") from exc
        for item in listing:
            path = rel + item.name
            try:
                item.name.encode("utf-8")
            except UnicodeEncodeError:
                self.result.omitted.append((path, "name is not UTF-8"))
                continue
            try:
                info = item.stat(follow_symlinks=False)
            except OSError:
                omitted.append({"name": item.name, "reason": "unreadable"})
                continue
            is_dir = stat.S_ISDIR(info.st_mode)
            if ignored(rules, path, is_dir):
                continue
            row = self.entry(item, path, info, rules, is_dir)
            if isinstance(row, str):
                omitted.append({"name": item.name, "reason": row})
                self.result.omitted.append((path, row))
            elif row is not None:
                entries.append(row)
        return put_tree(self.repo, entries, omitted)

    def entry(self, item: os.DirEntry, path: str, info, rules, is_dir) -> dict | str | None:
        name = item.name
        if is_dir:
            return {"mode": DIR, "name": name, "oid": self.tree(Path(item.path), path + "/", rules)}
        if stat.S_ISLNK(info.st_mode):
            target = os.fsencode(os.readlink(item.path))
            return {"mode": LINK, "name": name, "oid": self.repo.put("blob", target, redact=False)}
        if not stat.S_ISREG(info.st_mode):
            return None  # sockets, fifos, devices: not workspace content
        if self.redact and self.redact.redacted(path):
            return "tineignore redact"
        if info.st_size > self.limit:
            return "size"
        self.result.files += 1
        if self.result.files > MAX_FILES:
            raise SnapshotError(f"workspace has more than {MAX_FILES} files")
        mode = EXEC if info.st_mode & 0o100 and os.name != "nt" else FILE
        key = _key(info)
        cached = self.old.get(path)
        if cached and cached[0] == key and self.repo.has(cached[1]):
            oid, scrubbed = cached[1], cached[2]
        else:
            try:
                data = _read_nofollow(item.path)
            except OSError:
                return "unreadable"
            self.result.bytes_read += len(data)
            oid, scrubbed = _store_file(self.repo, data)
        self.result.cache[path] = (key, oid, scrubbed)
        return {"mode": mode, "name": name, "oid": oid, **({"redacted": True} if scrubbed else {})}


def _redact_globs(root: Path):
    from opentine._tineignore import load

    rules = load(root)
    return rules if rules.redact else None


def _read_nofollow(path: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError(f"{path} is no longer a regular file")
        return handle.read()


def snapshot(
    repo: Any,
    root: str | Path,
    *,
    ignore: Iterable[str] = (),
    max_file_bytes: int = MAX_FILE_BYTES,
    cache: StatCache | None = None,
) -> Snapshot:
    """Store *root* as a tree in *repo*; pass the previous turn's ``cache`` to skip rereads."""
    base = Path(root)
    if base.is_symlink() or not base.is_dir():
        raise SnapshotError(f"{root} is not a directory")
    walker = _Walker(repo, base, root_rules(base, ignore), max_file_bytes, cache or {})
    walker.result.oid = walker.tree(base, "", walker.rules)
    return walker.result


__all__ = ["MAX_FILE_BYTES", "Snapshot", "SnapshotError", "StatCache", "link_tree", "snapshot"]
