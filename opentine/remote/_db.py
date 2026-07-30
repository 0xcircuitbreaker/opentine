"""SQLite connection factory that closes its handle, which Windows requires."""

from __future__ import annotations

import contextlib
import os
import sqlite3
from collections.abc import Iterator


@contextlib.contextmanager
def open_db(path: object) -> Iterator[sqlite3.Connection]:
    """Yield a WAL connection and close it so the file lock is released.

    sqlite3's own context manager commits but never closes, so every
    ``with connect() as database:`` leaked an open handle. On POSIX that is
    benign, but on Windows an open WAL handle locks the file and the next
    open of the same database fails with ``PermissionError`` (WinError 5).
    Closing in the ``finally`` fixes it on every platform.
    """
    connection = sqlite3.connect(path, timeout=30)
    try:
        # Inside the try: if the pragma raises (the path is not a database, or
        # the lock times out), the handle must still close or it leaks the very
        # lock this module exists to release.
        connection.execute("PRAGMA journal_mode=WAL")
        # sqlite3 creates the database (and its WAL/shm siblings) with the
        # process umask, typically world-readable, while every other file this
        # server writes is 0600. The database holds tenant run inventory and
        # the audit chain, so it gets the same treatment as its siblings.
        for sibling in (path, f"{path}-wal", f"{path}-shm"):
            try:
                os.chmod(sibling, 0o600)
            except OSError:
                pass
        with connection:
            yield connection
    finally:
        connection.close()
