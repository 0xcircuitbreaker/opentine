"""Bounded ref reads and atomic local ref commits."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from opentine._canon import _fsync_dir
from opentine.kernel import KernelError, parse_oid
from opentine.repository._paths import durable_directory, internal_path
from opentine.repository._reflog import append_reflog, reflog_entry

MAX_REF_BYTES = 256


def read_ref_oid(base: Path, normalized: str) -> str | None:
    path = internal_path(base, "refs", *Path(normalized).parts)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise KernelError("repository ref is not a private regular file")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(MAX_REF_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(raw) > MAX_REF_BYTES:
        raise KernelError("repository ref exceeds its size limit")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise KernelError("repository ref is not ASCII") from exc
    oid = text.removesuffix("\r\n").removesuffix("\n")
    if text not in {oid, oid + "\n", oid + "\r\n"} or any(char.isspace() for char in oid):
        raise KernelError("repository ref is not canonically encoded")
    parse_oid(oid)
    return oid


def commit_ref(
    base: Path,
    normalized: str,
    new_oid: str,
    expected_old: str | None,
    check_expected: bool,
    actor: str,
) -> None:
    ref_path = internal_path(base, "refs", *Path(normalized).parts)
    durable_directory(ref_path.parent)
    lock_path = ref_path.with_name(ref_path.name + ".lock")
    # The staging name must collide with nothing: not another ref's file, and not
    # another ref's guard lock. ``normalize_ref`` rejects a component ending in
    # ".lock", "." or " ", so "<ref>..lock" can be neither a ref (it ends in
    # ".lock") nor the lock of ref "<ref>." (which cannot exist). A plain
    # "<ref>.new.lock" is *not* safe: it is exactly the guard lock of the legal
    # sibling ref "<ref>.new", so updating "x" would fail against, and then in its
    # cleanup delete, the live lock held by a writer of "x.new".
    write_path = ref_path.with_name(ref_path.name + "..lock")
    try:
        guard_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError as exc:
        raise ValueError(
            f"ref {normalized!r} is locked by a concurrent write; if no writer is "
            f"running, remove {lock_path.name!r} from the repository refs directory"
        ) from exc
    write_fd = -1
    ref_replaced = False
    try:
        with os.fdopen(guard_fd, "wb"):
            guard_fd = -1
        old = read_ref_oid(base, normalized)
        if check_expected and old != expected_old:
            raise ValueError(f"concurrent ref update: expected {expected_old!r}, found {old!r}")
        entry = reflog_entry(normalized, old, new_oid, actor)
        write_fd = os.open(write_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        with os.fdopen(write_fd, "wb") as handle:
            write_fd = -1
            handle.write((new_oid + "\n").encode("ascii"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(write_path, ref_path)
        ref_replaced = True
        _fsync_dir(ref_path.parent)
        append_reflog(base, normalized, entry)
    finally:
        for descriptor in (guard_fd, write_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        write_path.unlink(missing_ok=True)
        lock_path.unlink(missing_ok=True)
        if ref_replaced:
            _fsync_dir(ref_path.parent)
