"""``tine prune``: find, and only on request delete, unreachable cold objects.

Safety rules (each one has a test):

* a dry run is the default; nothing is deleted without ``delete=True``;
* roots are scanned conservatively (see ``_prune_roots``) and an unreadable
  root source refuses the delete;
* an object is a candidate only when it is unreachable *and* was last written
  at least ``min_age`` seconds ago (never less than :data:`MIN_GRACE`, which exceeds the hourly
  pack-freshen throttle). Its age
  is its loose file's mtime, or its pack's: a writer that finds an object
  already stored re-touches it (``_storage._freshen``), so an object a live
  recorder is about to reference again is young, never a candidate;
* the delete runs under the gc lock, re-plans inside it, re-checks each age
  just before removing, and rewrites a pack (written and read back first)
  instead of editing it; a pack re-touched meanwhile aborts the rewrite.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from opentine import _codec
from opentine.kernel import KernelError
from opentine.repository._gc import GC_LEVEL, gc_lock, pack_format
from opentine.repository._gc_tidy import loose_entries, remove_empty_dir
from opentine.repository._objects import iter_typed_object_oids
from opentine.repository._pack_write import load_pack, write_pack
from opentine.repository._packs import pack_set
from opentine.repository._paths import internal_path
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


def plan(repo, *, min_age: float = DEFAULT_MIN_AGE, git_links: bool = True) -> PrunePlan:
    min_age = max(MIN_GRACE, float(min_age))
    roots = file_roots(repo.path)
    roots.update(iter_typed_object_oids(repo.path, {"annotation", "attestation"}, limit=10**8))
    if git_links:
        roots.update(git_roots(repo.worktree))
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
        result = plan(repo, min_age=min_age, git_links=git_links)
        cutoff = result.cutoff
        victims = set(result.candidates)
        _rewrite_packs(repo, victims, cutoff, result)
        for oid in sorted(victims):
            path = repo._object_path(oid)
            try:
                if os.lstat(path).st_mtime > cutoff:
                    continue  # re-touched by a writer since the plan
            except FileNotFoundError:
                continue
            path.unlink(missing_ok=True)
            remove_empty_dir(path.parent)
            result.deleted += 1
        pack_set(repo.path).refresh()
        return result


def _rewrite_packs(repo, victims: set[str], cutoff: float, result: PrunePlan) -> None:
    _, _, members = _ages(repo)
    affected = sorted(digest for digest, oids in members.items() if oids & victims)
    if not affected:
        return
    stamps = {d: os.stat(internal_path(repo.path, "packs", f"{d}.tpk")).st_mtime for d in affected}
    if any(stamp > cutoff for stamp in stamps.values()):
        raise KernelError("a pack was re-touched by a writer since the plan; rerun prune")
    keep = sorted(set().union(*(members[d] for d in affected)) - victims)
    objects = [(oid, repo.raw(oid)) for oid in keep]
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
    for old in affected:
        path = internal_path(repo.path, "packs", f"{old}.tpk")
        if os.stat(path).st_mtime != stamps[old]:
            raise KernelError("a pack was re-touched by a writer during prune; rerun prune")
        for suffix in (".tidx", ".tpk"):
            internal_path(repo.path, "packs", old + suffix).unlink(missing_ok=True)
        result.rewritten_packs += 1
    loose = {oid for oid, _, _ in loose_entries(repo.path)}
    result.deleted += len((victims - loose) & set().union(*members.values()))
