"""Bounded ref reads and atomic local ref commits."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

from opentine._canon import _fsync_dir
from opentine.kernel import KernelError, parse_oid
from opentine.repository._paths import durable_directory, internal_path
from opentine.repository._reflog import append_reflog, reflog_entry

MAX_REF_BYTES = 256


def read_ref_oid(base: Path, normalized: str) -> str | None:
    path = internal_path(base, "refs", *Path(normalized).parts)
    for attempt in range(50):
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            break
        except FileNotFoundError:
            return None
        except PermissionError:  # Windows: the ref is mid-replace (delete pending)
            if os.name != "nt" or attempt == 49:
                raise
            time.sleep(0.002)
    try:
        info = os.fstat(fd)
        # Reject a *hardlinked* ref (nlink > 1), not an unlinked one. A concurrent
        # commit_ref replaces this path, which unlinks the inode we already hold
        # open, so fstat legitimately reports nlink == 0 — and "!= 1" called that
        # corruption, failing readers and fsck on a perfectly healthy repository.
        # The bytes behind an unlinked descriptor are still a valid past ref value,
        # and the compare-and-swap catches staleness on write.
        if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
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


def _replace(source: Path, target: Path) -> None:
    """``os.replace``, retried briefly on Windows sharing violations.

    On Windows a rename fails while any process holds either file open, and
    readers (``read_ref``, prune's root scan) open ref files for a moment.
    """
    for attempt in range(50):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if os.name != "nt" or attempt == 49:
                raise
            time.sleep(0.02)


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
    from opentine.repository._ref_txn import locked_after_recovery

    try:
        # The lock records pid/host/time; one left by a crashed writer on this
        # host is broken automatically, anything else is reported, never guessed.
        # A crashed multi-ref transaction is rolled forward first (_ref_txn).
        locked_after_recovery(base, [lock_path])
    except ValueError as exc:
        raise ValueError(
            f"ref {normalized!r} is locked by a concurrent writer ({lock_path}); if no "
            "opentine process is writing this repository, delete that file"
        ) from exc
    guard_fd = -1
    write_fd = -1
    ref_replaced = False
    try:
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
        _replace(write_path, ref_path)
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
        try:
            write_path.unlink(missing_ok=True)
        except PermissionError:  # Windows: a reader still holds it; it is not a ref
            pass
        lock_path.unlink(missing_ok=True)
        if ref_replaced:
            _fsync_dir(ref_path.parent)
