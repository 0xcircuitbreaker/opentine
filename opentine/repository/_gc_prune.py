"""``tine prune``: find, and only on request delete, unreachable cold objects.

Safety rules (each one has a test):

* a dry run is the default; nothing is deleted without ``delete=True``;
* roots are scanned conservatively (see ``_prune_roots``) and an unreadable
  root source refuses the delete;
* an object is a candidate only when it is unreachable *and* was last written
  at least ``min_age`` seconds ago (never less than :data:`MIN_GRACE`, which exceeds the hourly
  pack-freshen throttle). Its age
  is its loose file's mtime, or its pack's: a writer that finds an object
  already stored, or links one, re-touches it (``_storage._freshen``,
  ``_link_touch``), so an object a live recorder is about to reference again
  is young, never a candidate;
* the delete runs under the gc lock, re-plans inside it, and rewrites a pack
  (written and read back first) instead of editing it;
* victims are moved into a quarantine first; then ages and reachability are
  checked again and anything young, re-touched or newly reachable is restored
  (``_prune_quarantine``, 0.35);
* held objects (``tine hold``) and everything they reach are roots.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from opentine import _codec
from opentine.kernel import KernelError
from opentine.repository._gc import GC_LEVEL, gc_lock, pack_format
from opentine.repository._gc_tidy import loose_entries
from opentine.repository._holds import held_oids, holds_path
from opentine.repository._objects import iter_typed_object_oids
from opentine.repository._pack_write import load_pack, write_pack
from opentine.repository._packs import pack_set
from opentine.repository._paths import internal_path
from opentine.repository._prune_quarantine import Quarantine, recover
from opentine.repository._prune_roots import file_roots, git_roots, reachable
from opentine.repository._storage import _PACK_FRESHEN

#: The floor on how young an unreachable object may be and still be pruned. A
#: writer re-touches a *pack* at most once per ``_PACK_FRESHEN`` seconds, so a
#: packed object a live recorder just reused can look that old; the floor sits
#: above the throttle (plus a margin for clock skew and slow writers), or prune
#: could delete it from under the recorder.
MIN_GRACE = float(_PACK_FRESHEN) + 600.0
DEFAULT_MIN_AGE = 14 * 86400.0


@dataclass
class PrunePlan:
    total: int = 0
    reachable: int = 0
    unreachable: int = 0
    unreachable_bytes: int = 0
    young: int = 0
    candidates: list[str] = field(default_factory=list)
    candidate_bytes: int = 0
    deleted: int = 0
    restored: int = 0
    rewritten_packs: int = 0
    cutoff: float = 0.0

    def summary(self) -> dict:
        data = dict(self.__dict__)
        data["candidates"] = len(self.candidates)
        return data


def _ages(repo) -> tuple[dict[str, float], dict[str, int], dict[str, set[str]]]:
    """Newest mtime and stored bytes per object, and each pack's members."""
    ages: dict[str, float] = {}
    sizes: dict[str, int] = {}
    members: dict[str, set[str]] = {}
    for oid, _, info in loose_entries(repo.path):
        ages[oid] = info.st_mtime
        sizes[oid] = info.st_size
    packs = pack_set(repo.path)
    packs.refresh()
    for digest in sorted(packs.blocks):
        try:
            mtime = os.stat(internal_path(repo.path, "packs", f"{digest}.tpk")).st_mtime
            single = load_pack(repo.path, digest)
        except (OSError, ValueError):
            continue
        members[digest] = set(single.where)
        for oid, (_, _, _, length) in single.where.items():
            ages[oid] = max(ages.get(oid, 0.0), mtime)
            sizes.setdefault(oid, length)
    return ages, sizes, members


def _roots(repo, git_links: bool) -> set[str]:
    roots = file_roots(repo.path)
    roots.update(held_oids(holds_path(repo)))  # scanned above too; this read fails closed
    roots.update(iter_typed_object_oids(repo.path, {"annotation", "attestation"}, limit=10**8))
    if git_links:
        roots.update(git_roots(repo.worktree))
    return roots


def plan(repo, *, min_age: float = DEFAULT_MIN_AGE, git_links: bool = True) -> PrunePlan:
    min_age = max(MIN_GRACE, float(min_age))
    roots = _roots(repo, git_links)
    ages, sizes, _ = _ages(repo)
    kept = reachable(repo, roots)
    cutoff = time.time() - min_age
    result = PrunePlan(total=len(ages), reachable=len(kept & set(ages)))
    for oid in sorted(set(ages) - kept):
        result.unreachable += 1
        result.unreachable_bytes += sizes.get(oid, 0)
        if ages[oid] <= cutoff:
            result.candidates.append(oid)
            result.candidate_bytes += sizes.get(oid, 0)
        else:
            result.young += 1
    result.cutoff = cutoff
    return result


def prune(
    repo, *, delete: bool = False, min_age: float = DEFAULT_MIN_AGE, git_links: bool = True
) -> PrunePlan:
    if not delete:
        return plan(repo, min_age=min_age, git_links=git_links)
    with gc_lock(repo.path):
        recover(repo)  # a crashed prune's quarantine goes back first
        result = plan(repo, min_age=min_age, git_links=git_links)
        victims = set(result.candidates)
        quarantine = Quarantine(repo)
        try:
            touched = _rewrite_packs(repo, victims, result, quarantine)
            for oid in sorted(victims):
                quarantine.move_loose(oid)
            # Moved: from now on a writer's touch finds nothing and refuses its link.
            young = quarantine.young(result.cutoff) | touched
            keep = quarantine.keep(_roots(repo, git_links) | young)
        except BaseException:
            quarantine.restore_all()
            raise
        result.restored = len(keep)
        result.deleted = quarantine.finish(keep)
        pack_set(repo.path).refresh()
        return result


def _rewrite_packs(repo, victims: set[str], result: PrunePlan, quarantine) -> set[str]:
    """Drop *victims* from their packs; return those whose pack a writer re-touched."""
    _, _, members = _ages(repo)
    affected = sorted(digest for digest, oids in members.items() if oids & victims)
    stamps = {d: os.stat(internal_path(repo.path, "packs", f"{d}.tpk")).st_mtime for d in affected}
    fresh = [d for d in affected if stamps[d] > result.cutoff]  # re-touched since the plan
    touched: set[str] = set().union(*(members[d] & victims for d in fresh))
    affected = [d for d in affected if d not in fresh]
    if not affected:
        return touched
    packed = set().union(*(members[d] for d in affected))
    for oid in sorted(victims & packed):
        quarantine.stash(oid, repo.raw(oid))
    objects = [(oid, repo.raw(oid)) for oid in sorted(packed - victims)]
    codec = getattr(repo, "_storage_codec", None)
    if codec in (None, "none") or not _codec.available(codec):
        codec = _codec.default_codec()
    if objects:
        level = GC_LEVEL if codec == "zstd" else 9
        digest = write_pack(repo.path, objects, codec, level, pack_format(repo))
        check = load_pack(repo.path, digest)
        for oid, raw in objects:
            if check.read(oid) != raw:
                raise KernelError(f"rewritten pack does not return {oid}; nothing was removed")
        affected = [d for d in affected if d != digest]
    for old in affected:  # unpublish first, then move the body aside
        internal_path(repo.path, "packs", f"{old}.tidx").unlink(missing_ok=True)
        if quarantine.park_pack(internal_path(repo.path, "packs", f"{old}.tpk")) != stamps[old]:
            touched |= members[old] & victims  # a writer reused one meanwhile
        result.rewritten_packs += 1
    return touched
