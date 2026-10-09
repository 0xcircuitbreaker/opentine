"""Open a sandboxed path without following anything swapped in after the check.

``fs._resolve`` decides a path is inside a root, then the tool opened it by name:
in between, a concurrent writer in the workspace could replace a directory with
a symlink to ``/etc`` or ``.git`` and the open followed it. Where the platform
can (POSIX ``dir_fd`` + ``O_NOFOLLOW``), the resolved path is reached from the
root one component at a time, refusing any symlink, so what opens is what was
checked. Elsewhere (Windows), the opened handle must be the file the path still
names, and a write truncates only after that check; a directory is listed
through its handle (``_fs_windows``).
"""

from __future__ import annotations

import errno
import os
import stat
from itertools import islice
from pathlib import Path

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_PRIVATE = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOINHERIT", 0) | getattr(os, "O_BINARY", 0)
WALKS = bool(_NOFOLLOW and _DIRECTORY) and {os.open, os.mkdir} <= os.supports_dir_fd
#: What a symlink (or a FIFO with no reader) met on the walk raises.
_SWAPPED = {errno.ELOOP, errno.ENOTDIR, errno.EMLINK, errno.ENXIO}


def open_file(root: Path, resolved: Path, *, write: bool = False) -> int:
    """A descriptor for the regular file at ``resolved``; a write is truncated.

    A write creates missing parent directories and the file. Hard-linked files
    are refused for writing (the write would reach every other name).
    """
    flags = (os.O_WRONLY | os.O_CREAT) if write else os.O_RDONLY
    # O_NONBLOCK: a FIFO swapped in for the file must not hang the agent.
    fd = _open(root, resolved, flags | _NONBLOCK, make_parents=write)
    try:
        status = os.fstat(fd)
        if not stat.S_ISREG(status.st_mode):
            raise ValueError(f"Path is not a regular file: {resolved}")
        if write and status.st_nlink > 1:
            raise PermissionError(f"Writing a hard-linked file is denied by policy: {resolved}")
        if write:
            os.ftruncate(fd, 0)
        if _NONBLOCK:
            os.set_blocking(fd, True)
    except BaseException:
        os.close(fd)
        raise
    return fd


def list_entries(root: Path, resolved: Path, limit: int) -> list[tuple[bool, str]]:
    """Up to ``limit + 1`` ``(is_dir, name)`` entries of the directory that was checked."""
    if os.name == "nt":
        from opentine.tools._fs_windows import list_directory

        return list_directory(resolved, limit)
    fd = None
    if WALKS and os.scandir in os.supports_fd:
        fd = _open(root, resolved, os.O_RDONLY | _DIRECTORY, make_parents=False)
    try:
        with os.scandir(resolved if fd is None else fd) as listing:
            found = list(islice(listing, limit + 1))
            return [(entry.is_dir(follow_symlinks=True), entry.name) for entry in found]
    finally:
        if fd is not None:
            os.close(fd)


def _open(root: Path, resolved: Path, flags: int, *, make_parents: bool) -> int:
    if not WALKS:
        return _open_checked(resolved, flags, make_parents=make_parents)
    parts = resolved.relative_to(root).parts
    fd = os.open(root, os.O_RDONLY | _DIRECTORY | _PRIVATE)
    try:
        if not parts:
            return os.dup(fd)
        for part in parts[:-1]:
            if make_parents:
                try:
                    os.mkdir(part, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _PRIVATE, dir_fd=fd)
            os.close(fd)
            fd = child
        return os.open(parts[-1], flags | _NOFOLLOW | _PRIVATE, 0o666, dir_fd=fd)
    except OSError as error:
        if error.errno not in _SWAPPED:
            raise
        raise PermissionError(f"Path changed while it was opened: {resolved}") from error
    finally:
        os.close(fd)


def _open_checked(resolved: Path, flags: int, *, make_parents: bool) -> int:
    if make_parents:
        resolved.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(resolved, flags | _PRIVATE, 0o666)
    try:
        # The handle must be the file the path names now, with no link on the way.
        now = os.path.normcase(resolved.resolve(strict=True))
        same = now == os.path.normcase(resolved) and os.path.samestat(
            os.fstat(fd), os.stat(resolved)
        )
    except OSError:
        same = False
    if not same:
        os.close(fd)
        raise PermissionError(f"Path changed while it was opened: {resolved}")
    return fd
