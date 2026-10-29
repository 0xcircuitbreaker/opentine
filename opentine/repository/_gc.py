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
from opentine.repository import _winretry
from opentine.repository._config import (
    STORAGE_V3,
    STORAGE_VERSION,
    STORAGE_VERSIONS,
    V3_NOTE,
    read_config,
    storage_version,
)
from opentine.repository._fanout_tidy import tidy_fanouts
from opentine.repository._gc_tidy import old_loose, remove_empty_dir, sweep_empty_fanout
from opentine.repository._lockfile import acquire
from opentine.repository._pack_write import load_pack, write_pack
from opentine.repository._packs import oid_of, pack_set
from opentine.repository._paths import atomic_bytes, internal_path

GC_LEVEL = 19  # packs are written once and read many times
FOOTPRINT_DIRS = ("objects", "packs", "refs", "logs", "fanouts", "txn")


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
    """(file bytes, allocated disk bytes) of objects, packs, refs, reflogs and state.

    Refs and reflogs are counted since 0.14: after a gc they are most of a
    repository's disk (one 4 KiB block per ref and per reflog file).
    """
    total = disk = 0
    for name in FOOTPRINT_DIRS:
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
    if config.get("version") in STORAGE_VERSIONS:
        return
    config.update(version=STORAGE_VERSION, storage={"compression": codec})
    atomic_bytes(path, canonical_json(config) + b"\n")
    repo._storage_codec = codec


def set_storage_version(repo, version: int, codec: str) -> None:
    """Write descriptor *version* (2 or 3), keeping every other key."""
    path = internal_path(repo.path, "config.json")
    config = read_config(path)
    config.update(version=version, storage={"compression": codec})
    config.pop("note", None)
    if version == STORAGE_V3:
        config["note"] = V3_NOTE
    atomic_bytes(path, canonical_json(config) + b"\n")
    repo._storage_codec = codec


def pack_format(repo) -> int:
    """The pack format a write uses now: 3 in a v3 repository, else 1.

    Read from the descriptor each time, never cached: a process that opened the
    repository before an upgrade or downgrade must follow it.
    """
    config = read_config(internal_path(repo.path, "config.json"))
    return 3 if storage_version(config) == STORAGE_V3 else 1


def _loose_oids(repo, min_age: float = 0.0, own: frozenset[str] = frozenset()) -> list[str]:
    return sorted(old_loose(repo.path, min_age, own=own))


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
        _winretry.unlink(path)  # contenders read the stamp briefly (Windows)


def gc(
    repo,
    *,
    repack: bool = False,
    codec: str | None = None,
    level: int | None = GC_LEVEL,
    keep_transfer_packs: bool = False,
    min_age: float = 0.0,
    merge_packs: list[str] | None = None,
    upgrade: bool = False,
    downgrade: bool = False,
    own: frozenset[str] = frozenset(),
) -> GcResult:
    """Pack loose objects (only those *min_age* seconds old or older).

    ``repack`` also rewrites every pack; *merge_packs* rewrites just those.
    ``upgrade`` moves the repository to storage version 3 and rewrites every
    pack in that format; ``downgrade`` rewrites every pack in the version-1
    pack format and returns the descriptor to version 2 (what 0.11-0.12 read).
    Neither ever happens implicitly. *own* oids are packed whatever their age.
    """
    if upgrade and downgrade:
        raise ValueError("choose one of --upgrade and --downgrade")
    configured = getattr(repo, "_storage_codec", None)
    chosen = codec or (configured if configured not in (None, "none") else None)
    chosen = chosen or _codec.default_codec()
    if not _codec.available(chosen):
        raise ValueError(f"{chosen} is not available; install opentine[zstd] or pass --codec zlib")
    with gc_lock(repo.path):
        # Already v3 with only format-3 packs: --upgrade has nothing to rewrite (it
        # used to repack everything into a byte-identical pack); loose still packs.
        rewrite = repack or downgrade or (upgrade and not _is_v3(repo, chosen))
        if upgrade:  # descriptor first: a crash leaves a v3 repo holding v1 packs
            set_storage_version(repo, STORAGE_V3, chosen)
        args = (repo, rewrite, chosen, level, keep_transfer_packs)
        result = _gc_locked(*args, (min_age, own), merge_packs, 1 if downgrade else None)
        if downgrade:  # descriptor last: until then 0.12 must keep refusing
            set_storage_version(repo, STORAGE_VERSION, chosen)
        tidy_fanouts(repo.path)  # finished fan-out state past its grace period
        return result


def _is_v3(repo, codec: str) -> bool:
    config = read_config(internal_path(repo.path, "config.json"))
    if storage_version(config) != STORAGE_V3 or repo._storage_codec != codec:
        return False
    packs = pack_set(repo.path)
    packs.refresh()
    return set(packs.blocks) <= set(packs.v3)


def _gc_locked(
    repo, repack: bool, chosen: str, level, keep_transfer_packs: bool, selection, merge_packs, fmt
) -> GcResult:
    before = footprint(repo.path)
    enable_storage(repo, chosen)
    fmt = fmt or pack_format(repo)
    packs = pack_set(repo.path)
    packs.refresh()
    held = {place[0] for place in packs.where.values()}
    old_packs = sorted(held if repack else held & set(merge_packs or ()))
    loose = _loose_oids(repo, *selection)  # (min_age, own oids)
    carried = {oid for oid, place in packs.where.items() if place[0] in old_packs}
    # Packed objects are read in block order: a run delta then resolves from the
    # snapshot read just before it, not from its block's start (0.14.1).
    raws: dict[str, bytes] = {}
    for oid in [*packs.in_block_order(sorted(carried)), *sorted(set(loose) - carried)]:
        raws[oid] = raw = repo.raw(oid)
        if oid_of(raw) != oid:
            raise KernelError(f"refusing to pack a corrupt object: {oid}")
    objects = sorted(raws.items())
    removed_packs = 0
    if objects:
        digest = write_pack(repo.path, objects, chosen, level if chosen == "zstd" else 9, fmt)
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
