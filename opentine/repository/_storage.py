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

from opentine import _codec
from opentine.kernel import KernelError
from opentine.repository._packs import MAX_OBJECT_BYTES, pack_set
from opentine.repository._paths import install_verified


def _read_loose(path) -> bytes | None:
    try:
        stored = path.read_bytes()
    except FileNotFoundError:
        return None
    try:
        return _codec.unwrap(stored, limit=MAX_OBJECT_BYTES)
    except _codec.CodecError as exc:
        raise KernelError(f"stored object cannot be decoded: {exc}") from exc


def read_object(repo, oid: str) -> bytes:
    """The canonical bytes of *oid*; ``KeyError`` when it is not stored."""
    raw = _read_loose(repo._object_path(oid))
    if raw is None:
        try:
            raw = pack_set(repo.path).read(oid)
        except _codec.CodecError as exc:
            raise KernelError(f"packed object cannot be decoded: {exc}") from exc
    if raw is None:
        raise KeyError(oid)
    return raw


def object_exists(repo, oid: str) -> bool:
    try:
        if repo._object_path(oid).is_file():
            return True
    except KernelError:
        return False
    try:
        return pack_set(repo.path).locate(oid) is not None
    except (KernelError, OSError, ValueError):
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
        found = pack_set(repo.path).locate(oid)
        if found is None:
            raise KeyError(oid) from None
        return found[3]
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
    if not path.exists() and pack_set(repo.path).locate(oid) is not None:
        return False

    def same(existing: bytes) -> bool:
        try:
            return _codec.unwrap(existing, limit=MAX_OBJECT_BYTES) == raw
        except _codec.CodecError:
            return False

    return install_verified(
        path,
        encode_for_storage(repo, raw),
        "object",
        equivalent=same,
        read_limit=MAX_OBJECT_BYTES + 64,
    )
