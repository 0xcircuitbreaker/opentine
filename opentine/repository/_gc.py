"""``tine gc`` / ``tine repack``: move loose objects into compressed packs.

The pack is written and read back object by object before anything loose is
removed, so an interrupted gc leaves every object readable (at worst twice). A
repository is upgraded to descriptor version 2 the first time it is packed:
earlier opentine releases then refuse it cleanly instead of failing on a
packed object.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from opentine import _codec
from opentine.kernel import KernelError, canonical_json
from opentine.repository._config import STORAGE_VERSION, read_config
from opentine.repository._gc_tidy import old_loose, remove_empty_dir, sweep_empty_fanout
from opentine.repository._lockfile import acquire
from opentine.repository._pack_write import load_pack, write_pack
from opentine.repository._packs import oid_of, pack_set
from opentine.repository._paths import atomic_bytes, internal_path

GC_LEVEL = 19  # packs are written once and read many times


@dataclass(frozen=True)
class GcResult:
    packed: int
    removed_loose: int
    removed_packs: int
    removed_transfer_packs: int
    bytes_before: int
    bytes_after: int
    disk_before: int
    disk_after: int
    codec: str


def footprint(tine: Path) -> tuple[int, int]:
    """(file bytes, allocated disk bytes) of the object and pack directories."""
    total = disk = 0
    for name in ("objects", "packs"):
        for directory, _, files in os.walk(internal_path(tine, name)):
            for file in files:
                try:
                    info = os.lstat(os.path.join(directory, file))
                except FileNotFoundError:  # a writer's temporary file, renamed meanwhile
                    continue
                total += info.st_size
                disk += getattr(info, "st_blocks", 0) * 512 or info.st_size
    return total, disk


def enable_storage(repo, codec: str) -> None:
    """Upgrade a version-1 descriptor to version 2 with *codec*, keeping other keys."""
    path = internal_path(repo.path, "config.json")
    config = read_config(path)
    if config.get("version") == STORAGE_VERSION:
        return
    config.update(version=STORAGE_VERSION, storage={"compression": codec})
    atomic_bytes(path, canonical_json(config) + b"\n")
    repo._storage_codec = codec


def _loose_oids(repo, min_age: float = 0.0) -> list[str]:
    return sorted(old_loose(repo.path, min_age))


def _remove_loose(repo, oid: str) -> None:
    # The emptied fan-out directory goes too (rmdir removes only an empty one); a
    # writer that raced it recreates it (``atomic_bytes`` retries).
    path = repo._object_path(oid)
    path.unlink(missing_ok=True)
    remove_empty_dir(path.parent)


@contextmanager
def gc_lock(root: Path) -> Iterator[None]:
    """One gc or repack at a time per repository.

    Two concurrent packers could each delete loose objects the other has not
    yet packed and published. The lock is a file created exclusively that
    records pid/host/time; a lock left by a crashed gc is taken over only once
    its process is provably gone on this host (POSIX and Windows alike, never by
    age), and ``OPENTINE_GC_BREAK_LOCK=1`` overrides it explicitly.
    """
    path = internal_path(root, "gc.lock")
    if os.environ.get("OPENTINE_GC_BREAK_LOCK") == "1":
        path.unlink(missing_ok=True)
    try:
        fd = acquire(path, 0o600)
    except FileExistsError:
        raise KernelError(
            f"another tine gc is running on this repository ({path}); if none is, "
            "delete that file or set OPENTINE_GC_BREAK_LOCK=1"
        ) from None
    try:
        os.close(fd)
        yield
    finally:
        path.unlink(missing_ok=True)


def gc(
    repo,
    *,
    repack: bool = False,
    codec: str | None = None,
    level: int | None = GC_LEVEL,
    keep_transfer_packs: bool = False,
    min_age: float = 0.0,
    merge_packs: list[str] | None = None,
) -> GcResult:
    """Pack loose objects (only those *min_age* seconds old or older).

    ``repack`` also rewrites every pack; *merge_packs* rewrites just those.
    """
    configured = getattr(repo, "_storage_codec", None)
    chosen = codec or (configured if configured not in (None, "none") else None)
    chosen = chosen or _codec.default_codec()
    if not _codec.available(chosen):
        raise ValueError(f"{chosen} is not available; install opentine[zstd] or pass --codec zlib")
    with gc_lock(repo.path):
        return _gc_locked(repo, repack, chosen, level, keep_transfer_packs, min_age, merge_packs)


def _gc_locked(
    repo, repack: bool, chosen: str, level, keep_transfer_packs: bool, min_age, merge_packs
) -> GcResult:
    before = footprint(repo.path)
    enable_storage(repo, chosen)
    packs = pack_set(repo.path)
    packs.refresh()
    held = {place[0] for place in packs.where.values()}
    old_packs = sorted(held if repack else held & set(merge_packs or ()))
    loose = _loose_oids(repo, min_age)
    carried = {oid for oid, place in packs.where.items() if place[0] in old_packs}
    selected = sorted(set(loose) | carried)
    objects: list[tuple[str, bytes]] = []
    for oid in selected:
        raw = repo.raw(oid)
        if oid_of(raw) != oid:
            raise KernelError(f"refusing to pack a corrupt object: {oid}")
        objects.append((oid, raw))
    removed_packs = 0
    if objects:
        digest = write_pack(repo.path, objects, chosen, level if chosen == "zstd" else 9)
        check = load_pack(repo.path, digest)
        expected = dict(objects)
        for oid in check.in_block_order():  # read back before anything is deleted
            if check.read(oid) != expected.get(oid):
                raise KernelError(f"new pack does not return {oid}; nothing was removed")
        for oid in loose:
            _remove_loose(repo, oid)
        for old in old_packs:
            if old == digest:
                continue
            for suffix in (".tidx", ".tpk"):  # unpublish first, then drop the body
                internal_path(repo.path, "packs", old + suffix).unlink(missing_ok=True)
            removed_packs += 1
    transfer = 0
    if not keep_transfer_packs:
        # Received transfer packs are kept only as a copy of what arrived; every
        # object in them is installed, so the copy is redundant once packed.
        directory = internal_path(repo.path, "packs")
        for name in sorted(os.listdir(directory)) if directory.exists() else []:
            if name.endswith(".pack"):
                internal_path(repo.path, "packs", name).unlink()
                transfer += 1
    packs.refresh()
    sweep_empty_fanout(repo.path)
    after = footprint(repo.path)
    return GcResult(
        len(objects), len(loose), removed_packs, transfer, *before[:1], after[0],
        before[1], after[1], chosen,
    )  # fmt: skip
