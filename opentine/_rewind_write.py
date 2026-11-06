"""Writes for ``tine rewind``: never into control directories, never via a link.

A run's recorded paths are untrusted. Restoring into ``.git/hooks`` or
``.github/workflows`` would turn a rewind into code execution, so those
directories are refused unless the caller opts in. Each file is written by
walking the root one component at a time with ``O_DIRECTORY | O_NOFOLLOW``
directory descriptors and replacing it through its parent's descriptor, so a
link swapped in after the plan was checked is not followed.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
from pathlib import Path

from opentine._rewind import RewindError

CONTROL_DIRS = (".git", ".tine", ".hg", ".svn", ".bzr", "_darcs", ".jj", ".pijul")
CONTROL_PREFIXES = (
    (".github", "workflows"),
    (".gitlab",),
    (".circleci",),
    (".buildkite",),
    (".husky",),
)
CONTROL_FILES = (".gitlab-ci.yml", ".gitmodules", ".gitattributes", ".pre-commit-config.yaml")


def control_reason(root: Path, path: Path) -> str:
    """Why *path* is a version-control or CI control file ("" when it is not)."""
    parts = path.relative_to(root).parts
    lowered = tuple(part.lower() for part in parts)
    if any(part in CONTROL_DIRS for part in lowered[:-1]):
        return "inside a version-control directory"
    if lowered[-1] in CONTROL_DIRS:  # a ``.git`` file redirects to another gitdir
        return "a version-control control file"
    if any(lowered[: len(prefix)] == prefix for prefix in CONTROL_PREFIXES):
        return "inside a CI configuration directory"
    if len(lowered) == 1 and lowered[0] in CONTROL_FILES:
        return "a version-control or CI control file"
    return ""


_SAFE = hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY") and os.open in os.supports_dir_fd


def _parent_fd(root: Path, path: Path, create: bool) -> tuple[int, str]:
    """An ``O_NOFOLLOW`` descriptor for *path*'s directory, and its last component."""
    parts = path.relative_to(root).parts
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(root, flags)
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, 0o777, dir_fd=fd)
                except FileExistsError:
                    pass
            try:
                child = os.open(part, flags, dir_fd=fd)
            except OSError as exc:
                raise RewindError(f"{path} goes through a symbolic link or non-directory") from exc
            os.close(fd)
            fd = child
    except BaseException:
        os.close(fd)
        raise
    return fd, parts[-1]


def write_confined(root: Path, path: Path, data: bytes, mode: int | None = None) -> None:
    """Atomically put *data* at *path* under *root*, following no link.

    *mode* (permission bits) is applied when given; otherwise an existing file
    keeps its mode."""
    if not _SAFE:  # no dirfd-relative opens here: the checked path is the best we have
        from opentine._codec_io import atomic_write_bytes

        atomic_write_bytes(path, data)
        if mode is not None:
            os.chmod(path, mode)
        return
    fd, name = _parent_fd(root, path, True)
    try:
        _replace_at(fd, name, data, mode)
    finally:
        os.close(fd)


def symlink_confined(root: Path, path: Path, target: str) -> None:
    """Replace *path* with a symbolic link to *target* (never resolved here)."""
    if not _SAFE:
        if path.is_symlink() or path.is_file():
            path.unlink()
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, path)
        return
    fd, name = _parent_fd(root, path, True)
    try:
        tmp = f".{name}.{secrets.token_hex(6)}.tmp"
        os.symlink(target, tmp, dir_fd=fd)
        try:
            os.replace(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
        except BaseException:
            os.unlink(tmp, dir_fd=fd)
            raise
    finally:
        os.close(fd)


def remove_confined(root: Path, path: Path, *, recursive: bool = True) -> None:
    """Remove the file, link or directory (tree) at *path*, following no link."""
    if not _SAFE:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path) if recursive else path.rmdir()
        elif path.is_symlink() or path.exists():
            path.unlink()
        return
    fd, name = _parent_fd(root, path, False)
    try:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            shutil.rmtree(name, dir_fd=fd) if recursive else os.rmdir(name, dir_fd=fd)
        else:
            os.unlink(name, dir_fd=fd)
    except FileNotFoundError:
        pass
    finally:
        os.close(fd)


def _replace_at(dir_fd: int, name: str, data: bytes, want: int | None = None) -> None:
    try:
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        info = None
    if info is not None and want is None and not stat.S_ISREG(info.st_mode):
        raise RewindError(f"{name} is not a regular file")
    if info is not None and stat.S_ISDIR(info.st_mode):
        shutil.rmtree(name, dir_fd=dir_fd)  # an exact tree puts a file where a directory was
        info = None
    keep = stat.S_IMODE(info.st_mode) if info is not None and stat.S_ISREG(info.st_mode) else None
    mode = want if want is not None else keep if keep is not None else 0o666
    tmp = f".{name}.{secrets.token_hex(6)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(tmp, flags, mode, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            if want is not None or keep is not None:
                os.fchmod(handle.fileno(), mode)
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except OSError:
            pass
        raise


__all__ = [
    "CONTROL_DIRS",
    "control_reason",
    "remove_confined",
    "symlink_confined",
    "write_confined",
]
