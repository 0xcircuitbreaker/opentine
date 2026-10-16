"""Read a pricing catalog file only if it is a regular file.

A catalog layer can come from a cloned workspace (``.tine/pricing.json``), and
git carries symlinks: one pointing at ``/dev/stdin``, ``/dev/tty`` or a FIFO
made every pricing load in that directory block on a read that never ends. The
file is opened non-blocking (so opening a FIFO cannot wait for a writer),
checked with ``fstat`` on the open descriptor, and refused unless it is a
regular file, before a single byte is read. A symlink to a regular file still
works: the check is on what the descriptor opened, not on the path.
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)


def read_regular(path: Path, limit: int) -> bytes:
    """At most ``limit + 1`` bytes of *path*; ``OSError`` unless a regular file."""
    descriptor = os.open(path, _FLAGS)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)
