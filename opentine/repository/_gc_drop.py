"""Remove packs a gc merged away, tolerating readers that still hold them (Windows).

A concurrent reader (another process's ``PackSet``) may have a merged-away
pack's ``.tidx`` or ``.tpk`` open, and Windows then refuses to delete it
(sharing violation) for as long as that reader keeps it. The merged pack
already holds every object, so gc must not fail over it: after the bounded
:mod:`_winretry` wait the file is left for a later gc. The order keeps every
intermediate state valid: the ``.tidx`` goes first (unpublish), so a refused
``.tidx`` leaves both files -- a published duplicate whose objects are also in
the merged pack, which :func:`shadowed` lets the next gc remove -- and a
refused ``.tpk`` is an unpublished body that hashes to its name, which fsck
accepts and :func:`~opentine.repository._reap.reap_temp` reclaims.
"""

from __future__ import annotations

from opentine.repository import _winretry
from opentine.repository._paths import internal_path


def shadowed(packs, held: set[str], written: str | None) -> list[str]:
    """Listed packs none of whose objects are read from them (all held elsewhere).

    *written* is the pack this gc just wrote: it may share a digest with a listed
    duplicate (the same objects merged again), and is never one to drop.
    """
    return sorted(set(packs.indexes) - held - {written})


def drop_pack(root, digest: str) -> bool:
    """Unpublish and delete pack *digest*; False if a reader kept its ``.tidx``."""
    for suffix in (".tidx", ".tpk"):  # unpublish first, then drop the body
        try:
            _winretry.unlink(internal_path(root, "packs", digest + suffix))
        except PermissionError:
            if not _winretry.WINDOWS:  # elsewhere a real denial
                raise
            return suffix == ".tpk"  # an unpublished body is left for reap
    return True
