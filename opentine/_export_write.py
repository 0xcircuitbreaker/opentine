"""Writing an export file: owner-only, atomic, and never onto a special file.

An export holds run content -- prompts, tool output, file contents -- so it is
written ``0600`` whatever was at the destination before. The shared atomic
writers copy the replaced file's mode, which turned ``--force`` over a
world-readable file into a world-readable export. A destination that exists and
is neither a regular file nor a symlink (a directory, FIFO or device) is refused
even with ``--force``: ``os.replace`` onto it fails or, for a FIFO opened by a
reader, hands the content to whoever is listening.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

EXPORT_MODE = 0o600


def unsafe_destination(path: Path) -> str | None:
    """Why *path* cannot be an export destination, or ``None`` if it can."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        return None
    return "destination exists and is not a regular file"


def write_private(path: Path, data: bytes) -> None:
    """Write *data* to *path* atomically, readable by its owner only."""
    reason = unsafe_destination(path)
    if reason:
        raise ValueError(f"{reason}: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp, EXPORT_MODE)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
