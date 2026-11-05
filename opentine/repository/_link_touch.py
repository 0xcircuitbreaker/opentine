"""Linking to a stored object counts as writing it, so ``tine prune`` keeps it.

``tine prune --delete`` deletes an unreachable object only when it is old, and
moves it into a quarantine before it re-checks its age and reachability (see
``_prune_quarantine``). A writer that links an object already stored (a new
event naming an old blob, a ref moved to an orphaned run) re-touches it first:

* the touch lands before prune moves the object: prune sees it young and
  restores it (with everything it reaches);
* prune moved it first: the touch finds nothing, and the writer refuses the link
  instead of committing a run or ref that names a missing object.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from opentine.kernel import KernelError, parse_oid
from opentine.repository._packs import pack_set
from opentine.repository._paths import internal_path
from opentine.repository._storage import _PACK_FRESHEN


def touch_stored(base: Path, oid: str) -> bool:
    """Re-touch *oid* where it is stored; ``False`` when it is not stored."""
    object_type, digest = parse_oid(oid)
    try:
        os.utime(internal_path(base, "objects", object_type, digest[:2], digest[2:]))
        return True
    except FileNotFoundError:
        pass
    except (KernelError, OSError):
        return True  # read-only store, or a path being deleted by a gc (Windows)
    packs = pack_set(base)
    for _ in range(2):  # a stale pack listing: rescan once
        found = packs.locate(oid)
        if found is None:
            return False
        pack = internal_path(base, "packs", f"{found[0]}.tpk")
        try:
            if time.time() - os.stat(pack).st_mtime >= _PACK_FRESHEN:
                os.utime(pack)
            return True
        except FileNotFoundError:
            packs.refresh()
        except OSError:
            return True
    return False


def _quarantined(base: Path, oid: str) -> bool:
    """Whether a ``tine prune --delete`` has moved *oid* into its quarantine."""
    object_type, digest = parse_oid(oid)
    name = f"{object_type}-{digest}"
    root = internal_path(base, "prune-quarantine")
    return any(root.glob(f"*/loose/{name}")) or any(root.glob(f"*/raw/{name}"))


def touch_links(repo, links, *, strict: bool = True) -> None:
    """Re-touch every object *links* names; refuse one that is no longer stored.

    With ``strict=False`` (object writes, whose callers may store a graph in any
    order) a link to an object not stored yet is allowed unless prune moved it.
    """
    shallow = None
    for oid in links:
        if touch_stored(repo.path, oid):
            continue
        if not strict and not _quarantined(repo.path, oid):
            continue
        shallow = repo._shallow_set() if shallow is None else shallow
        if oid not in shallow:
            raise KernelError(f"missing linked object: {oid} (deleted by a concurrent prune?)")
