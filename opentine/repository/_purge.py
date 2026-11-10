"""``tine purge OID``: remove a blob's bytes, keep its oid, leave a tombstone (0.46).

The order is what makes a purge safe to interrupt:

1. under the gc lock (one gc, prune or purge at a time), a crashed prune's
   quarantine is restored first, exactly as ``tine prune --delete`` does;
2. the oid joins the shallow boundary list, so every event that links the blob
   still resolves its link (``_link_exists``) once the bytes are gone;
3. the signed tombstone is written (``_tombstones``);
4. the bytes move into a prune quarantine (``_prune_quarantine``): a loose
   file is renamed there, a packed copy is stashed there while its pack is
   rewritten without it (``_gc_prune._rewrite_packs``), and every kept transfer
   pack (``packs/<id>.pack``, a byte-exact copy of objects held elsewhere) that
   carries it is dropped; then the quarantine is finished with nothing kept.
   Packs that name a zstd dictionary (0.50) are rewritten too and the old
   dictionaries deleted, since a dictionary may hold text of the blob.

The derived search index can hold text from the blob, so it is deleted (search
falls back to the scan until ``tine repo-search --rebuild-index``). A blob
reachable from a hold (``tine hold``) is refused: a legal hold outranks a purge.
"""

from __future__ import annotations

import os
from typing import Any

from opentine._tombstone import well_formed
from opentine.kernel import KernelError, parse_oid
from opentine.repository import _pack_dicts, _tombstones
from opentine.repository._gc import gc_lock
from opentine.repository._gc_prune import PrunePlan, _rewrite_packs
from opentine.repository._holds import held_oids, holds_path
from opentine.repository._paths import atomic_bytes, internal_path
from opentine.repository._prune_quarantine import Quarantine, recover
from opentine.repository._prune_roots import reachable
from opentine.repository._shallow import encode_shallow, shallow_lock
from opentine.repository.pack import inspect_pack


def _check_target(repo: Any, oid: str) -> None:
    if parse_oid(oid)[0] != "blob":
        raise ValueError(f"only a blob can be purged: {oid}")
    if not repo.has(oid):
        raise KeyError(f"no such blob in this repository: {oid}")
    held = held_oids(holds_path(repo))
    if held and oid in reachable(repo, held):
        raise ValueError(f"{oid} is under a hold (`tine hold`); release it before purging")


def _add_boundary(repo: Any, oid: str) -> None:
    path = internal_path(repo.path, "shallow")
    with shallow_lock(path):
        atomic_bytes(path, encode_shallow(repo.shallow_oids() | {oid}))
        repo._invalidate_shallow()


def _drop_kept_packs(repo: Any, oid: str) -> int:
    """Delete every kept transfer pack that carries *oid*; return how many."""
    directory = internal_path(repo.path, "packs")
    dropped = 0
    for path in sorted(directory.glob("*.pack")) if directory.is_dir() else []:
        try:
            _, objects, _ = inspect_pack(path.read_bytes())
        except (KernelError, OSError):
            continue  # fsck names it; it cannot be served either
        if any(found == oid for found, _ in objects):
            path.unlink()
            dropped += 1
    return dropped


def _dict_packs(repo: Any) -> frozenset[str]:
    """Packs to rewrite because a zstd dictionary (0.50) may hold the blob's bytes.

    A dictionary is trained on stored objects, so any of them may carry text of
    the purged blob. The writer's hint goes first, so the rewrite trains afresh
    on what stays (or writes plain zstd), and every pack naming an old
    dictionary is rewritten; ``tidy`` then deletes the old dictionaries.
    """
    if not _pack_dicts.stored(repo.path):
        return frozenset()
    _pack_dicts.forget_latest(repo.path)
    return frozenset(_pack_dicts.naming_packs(repo.path))


def _drop_search_index(repo: Any) -> None:
    index = os.path.join(repo.path, "index", "search.sqlite")
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(index + suffix)
        except FileNotFoundError:
            pass


def purge(repo: Any, record: dict[str, Any]) -> dict[str, Any]:
    """Purge ``record["oid"]`` and store *record* (a signed tombstone)."""
    oid = well_formed(record)["oid"]
    with gc_lock(repo.path):
        recover(repo)
        if _tombstones.read(repo, oid) is not None and not repo.has(oid):
            return {"oid": oid, "purged": False, "already": True, "packs_rewritten": 0}
        _check_target(repo, oid)
        _add_boundary(repo, oid)
        _tombstones.write(repo, record)
        quarantine = Quarantine(repo)
        plan = PrunePlan(cutoff=float("inf"))
        try:
            _rewrite_packs(repo, {oid}, plan, quarantine, also=_dict_packs(repo))
            quarantine.move_loose(oid)
            dropped = _drop_kept_packs(repo, oid)
        except BaseException:
            quarantine.restore_all()
            raise
        quarantine.finish(set())
        from opentine.repository._packs import pack_set

        pack_set(repo.path).refresh()
        _pack_dicts.tidy(repo.path)  # the old dictionaries no pack names now
        _drop_search_index(repo)
    if repo.has(oid):
        raise KernelError(f"purge left a readable copy of {oid}")
    return {
        "oid": oid,
        "purged": True,
        "already": False,
        "packs_rewritten": plan.rewritten_packs + dropped,
    }


__all__ = ["purge"]
