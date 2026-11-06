"""gc's ref housekeeping: fold loose refs into ``packed-refs`` (``_packed_refs``).

:func:`pack_refs` runs in two steps, like ``git pack-refs``:

1. under ``packed-refs.lock``, merge every loose value into the packed file
   (read without the refs' locks: a value that moves meanwhile stays loose);
2. for each loose ref, under its own lock (never waited for: a busy ref is
   left loose), remove the file only if it still equals its packed value.

A crash anywhere leaves loose refs that shadow their packed values, so no
reader ever sees a value that was not current. Loose refs are removed only in a
repository that opted in (:func:`enable`), which 0.36 and older refuse to open.
"""

from __future__ import annotations

from pathlib import Path

from opentine._canon import _fsync_dir
from opentine.repository import _winretry
from opentine.repository._config import V4_MIN_READER, _to_v4, read_config, rewrite_config
from opentine.repository._packed_refs import (
    MIN_READER,
    packed_lock,
    read_packed,
    refs_packed,
    write_packed,
)
from opentine.repository._paths import durable_directory, internal_path
from opentine.repository._ref_store import loose_refs, read_loose_oid


def _ref_file(base: Path, name: str) -> Path:
    return internal_path(base, "refs", *Path(name).parts)


def _ref_lock(base: Path, name: str) -> Path:
    path = _ref_file(base, name)
    return path.with_name(path.name + ".lock")


def pack_refs(base: Path) -> int:
    """Fold loose refs into packed-refs; the number of loose files removed."""
    from opentine.repository._ref_txn import _locked_once

    lock = packed_lock(base)
    try:
        packed = read_packed(base)
        loose = loose_refs(base)
        merged = {**packed, **loose}
        if merged != packed:
            write_packed(base, merged)
    finally:
        _winretry.unlink(lock)
    removed = 0
    for name, oid in sorted(loose.items()):
        path = _ref_file(base, name)
        try:
            held = _locked_once(base, [_ref_lock(base, name)])
        except ValueError:
            continue  # being written right now: it stays loose until the next gc
        try:
            if read_loose_oid(base, name) == oid and read_packed(base).get(name) == oid:
                _winretry.unlink(path)
                _fsync_dir(path.parent)
                removed += 1
        except PermissionError:
            continue  # Windows: still held open by a reader; it stays loose (same value)
        finally:
            _winretry.unlink_all(held)
    return removed


def unpack_refs(base: Path) -> int:
    """Write every packed-only ref loose again and remove packed-refs; the count."""
    from opentine.repository._ref_txn import _write_ref, locked_after_recovery

    names = sorted(read_packed(base))
    locks = [_ref_lock(base, name) for name in names]
    held = locked_after_recovery(base, locks) if locks else []
    written = 0
    try:
        lock = packed_lock(base)  # after the ref locks: the order delete_ref takes them
        try:
            for name, oid in sorted(read_packed(base).items()):
                if read_loose_oid(base, name) is None:
                    durable_directory(_ref_file(base, name).parent)
                    _write_ref(base, name, oid)
                    written += 1
            write_packed(base, {})
        finally:
            _winretry.unlink(lock)
    finally:
        _winretry.unlink_all(list(reversed(held)))
    return written


def _version(text: object) -> tuple[int, ...]:
    return tuple(int(part) for part in str(text).split("."))


def _min_reader(config: dict[str, object], version: str) -> None:
    """Raise ``min_reader`` to *version* (never lower one a newer feature set)."""
    if _version(config.get("min_reader", "0.0.0")) < _version(version):
        config["min_reader"] = version


def enable(repo) -> None:
    """Opt *repo* in: object format 4 plus ``refs: packed`` and ``min_reader`` 0.37.0."""

    def change(config: dict) -> bool:
        if refs_packed(config) and _version(config["min_reader"]) >= _version(MIN_READER):
            return False
        _to_v4(config)
        config["refs"] = "packed"
        _min_reader(config, MIN_READER)
        return True

    rewrite_config(repo.path, change)  # descriptor first, then loose refs go


def disable(repo) -> int:
    """Write every ref loose again, then drop the opt-in (descriptor last).

    Under the gc lock, so no gc packs refs again between the two steps."""
    from opentine.repository._gc import gc_lock

    def change(config: dict) -> bool:
        if not refs_packed(config):
            return False
        del config["refs"]
        if config.get("min_reader") == MIN_READER:
            config["min_reader"] = V4_MIN_READER
        return True

    with gc_lock(repo.path):
        written = unpack_refs(repo.path)
        rewrite_config(repo.path, change)
    return written


def housekeep(repo) -> int:
    """gc's last step: finished fan-out state, then refs in an opted-in repository."""
    from opentine.repository._fanout_tidy import tidy_fanouts

    tidy_fanouts(repo.path)
    config = read_config(internal_path(repo.path, "config.json"))
    return pack_refs(repo.path) if refs_packed(config) else 0
