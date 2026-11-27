"""X18 (0.37): reclaim temporary files left behind by killed writers.

Every repository writer stages a file next to its target and renames it into
place: ``.<name>.<8 random>`` (``atomic_bytes``, reflogs) or ``.<name>.<8
random>.tmp`` (``atomic_write_text``/``atomic_write_bytes``). A writer killed
between the two leaves that file for ever; likewise a pack body renamed in
without the ``.tidx`` that would publish it. ``tine gc`` removes such a file only
once it is :data:`REAP_AGE` seconds old: a live writer renames its file within
moments, so an old one has no owner. Temporary files are never objects, so a
hold (which names objects) never covers one; links and anything that does not
match the staging pattern are left alone.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

from opentine.repository import _winretry

#: Staging files younger than this (seconds) may still belong to a live writer.
REAP_AGE = 3600.0
# mkstemp's random part is 8 characters from [a-z0-9_].
_STAGING = re.compile(r"\..+\.[a-z0-9_]{8}(\.tmp)?")
_PACK_BODY = re.compile(r"[0-9a-f]{64}\.tpk")


def _unpublished_pack(directory: str, name: str) -> bool:
    """A ``packs/<digest>.tpk`` whose ``.tidx`` never landed (writer killed between renames)."""
    return (
        os.path.basename(directory) == "packs"
        and _PACK_BODY.fullmatch(name) is not None
        and not os.path.lexists(os.path.join(directory, name[:64] + ".tidx"))
    )


def _reap_pack(path: str, seen: os.stat_result) -> bool:
    """Remove the stale pack body *seen* at *path*, never one a writer has since put there.

    Unlinking by name could delete a body a concurrent writer just renamed over
    the stale one (same digest) and is about to publish. Rename it aside first:
    whatever was taken is restored unless it is the stale file and still unpublished.
    """
    aside = f"{os.path.dirname(path)}/.{os.path.basename(path)}.reap{os.urandom(2).hex()}"
    os.rename(path, aside)
    taken = os.lstat(aside)
    if (taken.st_dev, taken.st_ino) == (seen.st_dev, seen.st_ino) and not os.path.lexists(
        path[:-4] + ".tidx"
    ):
        _winretry.unlink(Path(aside))
        return True
    try:
        os.link(aside, path)  # same digest, same bytes; a newer copy wins if present
    except FileExistsError:
        pass
    os.unlink(aside)
    return False


def is_staging(name: str) -> bool:
    return _STAGING.fullmatch(name) is not None


def reap_temp(tine: Path, *, min_age: float = REAP_AGE) -> int:
    """Delete staging files under *tine* older than *min_age* s; how many went."""
    cutoff, reaped = time.time() - min_age, 0
    for directory, dirs, files in os.walk(tine):  # never follows directory links
        dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(directory, name))]
        for name in files:
            pack = _unpublished_pack(directory, name)
            if not (pack or is_staging(name)):
                continue
            path = os.path.join(directory, name)
            try:
                info = os.lstat(path)
                if os.path.islink(path) or info.st_mtime > cutoff:
                    continue
                if pack:
                    if not _reap_pack(path, info):
                        continue
                else:
                    _winretry.unlink(Path(path))
            except OSError:  # renamed or removed by its writer meanwhile
                continue
            reaped += 1
    return reaped
