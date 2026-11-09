"""Bounded ref reads and atomic local ref commits."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from opentine._canon import _fsync_dir
from opentine.kernel import KernelError, parse_oid
from opentine.repository import _winretry
from opentine.repository._packed_refs import read_packed
from opentine.repository._paths import durable_directory, internal_files, internal_path
from opentine.repository._ref_retry import RefCasMismatch, RefLockContended
from opentine.repository._reflog import append_reflog, reflog_entry
from opentine.repository._refs import normalize_ref

MAX_REF_BYTES = 256


def read_ref_oid(base: Path, normalized: str) -> str | None:
    """The loose ref's value, else its packed one (``_packed_refs``), else ``None``."""
    value = read_loose_oid(base, normalized)
    return read_packed(base).get(normalized) if value is None else value


def loose_refs(base: Path) -> dict[str, str]:
    """Every loose ref by name (illegal names and lock files are not refs)."""
    refs: dict[str, str] = {}
    root = internal_path(base, "refs")
    for path in sorted(internal_files(base, "refs")):
        if path.name.casefold().endswith(".lock"):
            continue
        try:  # a name that is not a legal ref is not a ref: one stray .DS_Store
            name = normalize_ref(path.relative_to(root).as_posix())
        except ValueError:  # used to raise here, so fsck saw a healthy repo as
            continue  # broken with zero refs, masking every real error behind it
        if (value := read_loose_oid(base, name)) is not None:
            refs[name] = value
    return refs


def list_all_refs(base: Path) -> dict[str, str]:
    """Packed refs overlaid by loose ones: one read of packed-refs, not one per ref."""
    packed = read_packed(base)
    loose = loose_refs(base)
    return dict(sorted({**packed, **loose}.items())) if packed else loose


def read_loose_oid(base: Path, normalized: str) -> str | None:
    path = internal_path(base, "refs", *Path(normalized).parts)
    try:  # Windows: a ref mid-replace (delete pending) is briefly unopenable
        fd = _winretry.open_fd(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
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


def commit_ref(
    base: Path,
    normalized: str,
    new_oid: str,
    expected_old: str | None,
    check_expected: bool,
    actor: str,
    *,
    log: bool = True,
) -> None:
    """Compare-and-swap one ref; ``log=False`` skips its reflog row.

    The reflog is history, not authority (SPEC 2.6): a live recorder logs its
    session's first and final positions, not one row per appended event.
    """
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
        raise RefLockContended(
            f"ref {normalized!r} is locked by a concurrent writer ({lock_path}); if no "
            "opentine process is writing this repository, delete that file"
        ) from exc
    guard_fd = -1
    write_fd = -1
    ref_replaced = False
    try:
        old = read_ref_oid(base, normalized)
        if check_expected and old != expected_old:
            raise RefCasMismatch(f"concurrent ref update: expected {expected_old!r}, found {old!r}")
        entry = reflog_entry(normalized, old, new_oid, actor)
        # Only a holder of the guard lock writes the staging file, so one that is
        # already there was left by a writer killed before its replace (a long
        # fsync window on Windows): it is garbage, and O_EXCL on it would wedge
        # every later write of this ref with FileExistsError.
        _winretry.unlink(write_path)
        write_fd = os.open(write_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(write_fd, "wb") as handle:
            write_fd = -1
            handle.write((new_oid + "\n").encode("ascii"))
            handle.flush()
            os.fsync(handle.fileno())
        _winretry.replace(write_path, ref_path)  # readers hold refs open briefly
        ref_replaced = True
        _fsync_dir(ref_path.parent)
        if log:
            append_reflog(base, normalized, entry)
    finally:
        for descriptor in (guard_fd, write_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        try:
            _winretry.unlink(write_path)
        except PermissionError:  # still held: it is not a ref, and O_EXCL reports it
            pass
        # Lock contenders (and prune's scan) read the lock briefly; outlast them.
        _winretry.unlink(lock_path)
        if ref_replaced:
            _fsync_dir(ref_path.parent)
