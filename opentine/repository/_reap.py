"""X18 (0.37): reclaim temporary files left behind by killed writers.

Every repository writer stages a file next to its target and renames it into
place: ``.<name>.<8 random>`` (``atomic_bytes``, reflogs) or ``.<name>.<8
random>.tmp`` (``atomic_write_text``/``atomic_write_bytes``). A writer killed
between the two leaves that file for ever. ``tine gc`` removes such a file only
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


def is_staging(name: str) -> bool:
    return _STAGING.fullmatch(name) is not None


def reap_temp(tine: Path, *, min_age: float = REAP_AGE) -> int:
    """Delete staging files under *tine* older than *min_age* s; how many went."""
    cutoff, reaped = time.time() - min_age, 0
    for directory, dirs, files in os.walk(tine):  # never follows directory links
        dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(directory, name))]
        for name in files:
            if not is_staging(name):
                continue
            path = os.path.join(directory, name)
            try:
                info = os.lstat(path)
                if os.path.islink(path) or info.st_mtime > cutoff:
                    continue
                _winretry.unlink(Path(path))
            except OSError:  # renamed or removed by its writer meanwhile
                continue
            reaped += 1
    return reaped
