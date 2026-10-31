"""Where an object's bytes live: loose (plain or compressed) or in a pack.

Every reader goes through :func:`read_object`, which returns the canonical
envelope bytes whatever the stored form, so ids, signatures, diffs and transfer
packs never see compression. Writers go through :func:`write_object`, which
compresses only in a repository configured for it (descriptor version 2) and
only when that saves space.
"""

from __future__ import annotations

import os
import stat
import time

from opentine import _codec
from opentine.kernel import KernelError, parse_oid
from opentine.repository._packs import MAX_OBJECT_BYTES, pack_set
from opentine.repository._paths import install_verified, internal_path

#: Passes over the loose store and the packs when a check hits a transient error.
#: A gc in another process publishes its pack, then deletes the loose copies and
#: their emptied fan-out directories; on Windows a path being deleted while any
#: handle is open on it is *delete-pending*, and inspecting it is an access error
#: (a ``KernelError`` from ``internal_path``), not "not found". Such an error is
#: never absence: the object is in the pack the gc published first (0.17.1).
_PASSES = 6


def _pause(attempt: int) -> None:
    time.sleep(min(0.002 * 2**attempt, 0.05))


def _unwrap(stored: bytes) -> bytes:
    try:
        return _codec.unwrap(stored, limit=MAX_OBJECT_BYTES)
    except _codec.CodecError as exc:
        raise KernelError(f"stored object cannot be decoded: {exc}") from exc


def read_object(repo, oid: str) -> bytes:
    """The canonical bytes of *oid*; ``KeyError`` when it is not stored."""
    parse_oid(oid)
    for attempt in range(_PASSES):
        error: Exception | None = None
        try:
            return _unwrap(repo._object_path(oid).read_bytes())
        except FileNotFoundError:
            pass
        except (KernelError, OSError) as exc:  # being deleted by a gc (Windows), or hostile
            error = exc
        try:
            raw = pack_set(repo.path).read(oid)
        except _codec.CodecError as exc:
            raise KernelError(f"packed object cannot be decoded: {exc}") from exc
        except OSError as exc:
            raw, error = None, error or exc
        if raw is not None:
            return raw
        if error is None:
            raise KeyError(oid)
        if attempt == _PASSES - 1:
            raise error
        _pause(attempt)
    raise AssertionError("unreachable")  # pragma: no cover


def object_exists(repo, oid: str) -> bool:
    try:
        parse_oid(oid)
    except KernelError:
        return False
    for attempt in range(_PASSES):
        unsure = False
        try:
            if repo._object_path(oid).is_file():
                return True
        except (KernelError, OSError):
            unsure = True  # being deleted by a gc (Windows): its pack decides
        try:
            if pack_set(repo.path).locate(oid) is not None:
                return True
        except (KernelError, OSError, ValueError):
            unsure = True
        if not unsure:
            return False
        if attempt < _PASSES - 1:
            _pause(attempt)
    return False


def is_loose_plain(repo, oid: str) -> bool:
    """Whether *oid* is a loose file holding its canonical bytes as they are."""
    try:
        with open(repo._object_path(oid), "rb") as handle:
            return not _codec.is_wrapped(handle.read(len(_codec.MAGIC)))
    except FileNotFoundError:
        return False


def canonical_size(repo, oid: str) -> int | None:
    """Uncompressed size of a compressed loose or packed object, else ``None``."""
    path = repo._object_path(oid)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        size = pack_set(repo.path).size(oid)
        if size is None:
            raise KeyError(oid) from None
        return size
    except OSError as exc:
        raise KernelError("repository object cannot be safely opened") from exc
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise KernelError("repository object is not a regular file")
        head = handle.read(len(_codec.MAGIC) + 11)
    if not _codec.is_wrapped(head):
        return None
    try:
        return _codec.declared_size(head)
    except _codec.CodecError as exc:
        raise KernelError(f"stored object cannot be decoded: {exc}") from exc


def storage_codec(repo) -> str | None:
    """The codec a write uses now in *repo*, or ``None`` for plain storage."""
    configured = getattr(repo, "_storage_codec", None)
    return None if configured is None else _codec.wanted(configured)


def encode_for_storage(repo, raw: bytes) -> bytes:
    codec = storage_codec(repo)
    if codec is None:
        return raw
    return _codec.wrap(raw, codec) or raw


def write_object(repo, oid: str, raw: bytes) -> bool:
    """Store *raw* for *oid* unless it is already held; ``True`` if written.

    An existing loose copy must hold the same canonical bytes (a corrupt one
    is refused, as before); a packed copy was checked against its id on read.
    """
    path = repo._object_path(oid)
    if not path.exists() and (found := pack_set(repo.path).locate(oid)) is not None:
        _freshen(internal_path(repo.path, "packs", f"{found[0]}.tpk"), _PACK_FRESHEN)
        return False

    def same(existing: bytes) -> bool:
        try:
            return _codec.unwrap(existing, limit=MAX_OBJECT_BYTES) == raw
        except _codec.CodecError:
            return False

    written = install_verified(
        path,
        encode_for_storage(repo, raw),
        "object",
        equivalent=same,
        read_limit=MAX_OBJECT_BYTES + 64,
    )
    if not written:
        _freshen(path, 0)
    return written


#: A packed object's age is its pack's mtime; re-touch a pack at most hourly.
_PACK_FRESHEN = 3600


def _freshen(path, slack: float) -> None:
    """Mark an object as just written again, so ``tine prune`` keeps it.

    A writer that finds an object already stored writes nothing; without this an
    unreachable old copy it is about to reference could be pruned in between.
    """
    try:
        if slack and time.time() - os.stat(path).st_mtime < slack:
            return
        os.utime(path)
    except OSError:
        pass  # read-only store: nothing can be pruned from it either
