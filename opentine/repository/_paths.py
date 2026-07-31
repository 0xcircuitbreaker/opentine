"""Confined filesystem helpers for local v3 repositories."""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

from opentine._canon import _fsync_dir
from opentine.kernel import KernelError


def linklike(path: Path) -> bool:
    """Recognize POSIX symlinks and Windows directory junctions."""
    junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (callable(junction) and junction())


def internal_path(root: Path, *parts: str) -> Path:
    """Return an internal path after rejecting traversal and symlink components."""
    root = Path(root)
    try:
        if linklike(root) or not root.is_dir():
            raise KernelError("repository root must be a real directory")
    except FileNotFoundError as exc:
        raise KernelError("repository root is missing") from exc
    candidate = root.joinpath(*parts)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise KernelError("repository path escapes its root") from exc
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise KernelError("invalid internal repository path")
    current = root
    for index, part in enumerate(relative.parts):
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            raise KernelError(f"repository path cannot be inspected: {relative}") from exc
        if stat.S_ISLNK(info.st_mode) or linklike(current):
            raise KernelError(f"repository path contains a symlink: {relative}")
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise KernelError(f"repository path contains a special file: {relative}")
        # `> 1`, not `!= 1`. A concurrent ref commit renames a staged file over this
        # path, and during rename() the kernel briefly has both names pointing at one
        # inode, so a reader can observe nlink == 2 — and an unlinked-but-open target
        # reads as 0. Either tripped "!= 1" and made an ordinary concurrent update
        # look like a hard-link attack on a healthy repository.
        if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
            raise KernelError(f"repository path contains a hard-linked file: {relative}")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise KernelError(f"repository path has a non-directory parent: {relative}")
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as exc:
        raise KernelError("repository path escapes its root") from exc
    return candidate


def internal_files(root: Path, branch: str) -> Iterator[Path]:
    """Walk an internal tree without following or accepting symlinks."""
    start = internal_path(root, branch)
    if not start.exists():
        return
    for directory, names, files in os.walk(start, followlinks=False):
        base = Path(directory)
        for name in names:
            path = internal_path(root, *(base / name).relative_to(root).parts)
            if not path.is_dir():
                raise KernelError("repository walk encountered a non-directory")
        for name in files:
            path = internal_path(root, *(base / name).relative_to(root).parts)
            if not path.is_file():
                raise KernelError("repository walk encountered a non-file")
            yield path


def durable_directory(path: Path) -> None:
    """Create missing parents and fsync each directory that gains a child."""
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(exist_ok=True)
        _fsync_dir(directory.parent)


#: Structural directories a v3 repository keeps. git and tar drop them while
#: empty, so a repo committed to version control loses them; open() recreates
#: them so the store survives a checkout or archive round trip.
LAYOUT_DIRS = ("objects", "refs/annotations", "refs/heads", "refs/tags", "logs", "packs", "indexes")


def ensure_layout(tine: Path) -> None:
    """Create the standard repository directories if any are absent."""
    durable_directory(tine)
    for directory in LAYOUT_DIRS:
        durable_directory(internal_path(tine, *Path(directory).parts))


def atomic_bytes(path: Path, data: bytes) -> None:
    """Atomically write bytes after the caller has confined ``path``."""
    durable_directory(path.parent)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_dir(path.parent)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def install_verified(
    path: Path,
    data: bytes,
    label: str,
    *,
    equivalent=None,
    read_limit: int | None = None,
) -> bool:
    """Write verified bytes once, rejecting corrupt same-name local state."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        atomic_bytes(path, data)
        return True
    except OSError as exc:
        raise KernelError(f"existing {label} cannot be safely read") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise KernelError(f"existing {label} is not a private regular file")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            existing = handle.read((read_limit or len(data)) + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    matches = existing == data
    if not matches and equivalent:
        try:
            matches = equivalent(existing)
        except KernelError as exc:
            raise KernelError(f"existing {label} does not match verified incoming bytes") from exc
    if not matches:
        raise KernelError(f"existing {label} does not match verified incoming bytes")
    return False
