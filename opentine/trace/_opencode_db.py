"""Opening OpenCode's session database read-only, and listing its sessions.

OpenCode keeps every session in one SQLite file
(``~/.local/share/opencode/opencode.db``; ``$XDG_DATA_HOME`` honoured) beside
tables that hold account tokens and credentials. The importer therefore:

* opens the file read-only (``mode=ro``; ``immutable=1`` only as a fallback when
  a read-only open of a WAL database is refused), with ``query_only``,
  ``trusted_schema=OFF`` and, where Python offers it, SQLite's defensive mode;
* checks that ``session``, ``message`` and ``part`` are real tables with the
  columns it reads, and refuses any other schema by name -- the schema is still
  changing upstream, and guessing at a renamed column would import nonsense;
* reads only those three tables, only the columns it needs, never the
  ``account``/``credential``/``session_share`` tables;
* bounds rows, bytes per row and total work (a progress handler aborts a query
  that runs too long), so a crafted database cannot make the import spin.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from urllib.parse import quote

#: ``<db>::<session id>`` names one session of a database as an import source.
SEP = "::"
MAX_ROWS = 400_000
MAX_ROW_BYTES = 16 * 1024 * 1024
MAX_SESSIONS = 1_000
#: SQLite VM steps one import may run before it is aborted.
MAX_VM_STEPS = 2_000_000_000
_PROGRESS_EVERY = 100_000
_COLUMNS = {
    "session": {"id", "parent_id", "title", "time_created", "time_updated"},
    "message": {"id", "session_id", "time_created", "data"},
    "part": {"id", "message_id", "session_id", "time_created", "data"},
}
_MAGIC = b"SQLite format 3\x00"


def default_db() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base).expanduser() / "opencode" / "opencode.db"


def looks_like_sqlite(path: str | Path) -> bool:
    try:
        with Path(path).open("rb") as handle:
            return handle.read(len(_MAGIC)) == _MAGIC
    except OSError:
        return False


def split_source(source: str) -> tuple[Path, str | None]:
    """``(database, session id or None)`` from ``db`` or ``db::session``."""
    head, sep, tail = source.rpartition(SEP)
    if sep and head and tail:
        return Path(head), tail
    return Path(source), None


def _regular(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError(f"refusing to open a symlinked OpenCode database: {path}")
    if not path.is_file():
        raise ValueError(f"not an OpenCode database file: {path}")
    return path.resolve()


def connect(path: Path) -> tuple[sqlite3.Connection, bool]:
    """A read-only, bounded connection, and whether it fell back to ``immutable``."""
    resolved = _regular(path)
    uri = "file:" + quote(resolved.as_posix(), safe="/:")
    try:
        connection = sqlite3.connect(uri + "?mode=ro", uri=True, timeout=1)
        connection.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchall()
        immutable = False
    except sqlite3.OperationalError:
        # A WAL database whose -shm this user cannot create opens only this way;
        # writes still in the -wal file are then not seen (reported as a warning).
        connection = sqlite3.connect(uri + "?mode=ro&immutable=1", uri=True, timeout=1)
        immutable = True
    _harden(connection)
    _check_schema(connection)
    return connection, immutable


def _harden(connection: sqlite3.Connection) -> None:
    for pragma in ("query_only=ON", "trusted_schema=OFF", "cell_size_check=ON"):
        connection.execute(f"PRAGMA {pragma}")
    if hasattr(connection, "setlimit"):  # Python 3.11+
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_ROW_BYTES)
    if hasattr(connection, "setconfig") and hasattr(sqlite3, "SQLITE_DBCONFIG_DEFENSIVE"):
        connection.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)  # Python 3.12+
    steps = [0]

    def progress() -> int:
        steps[0] += _PROGRESS_EVERY
        return 1 if steps[0] > MAX_VM_STEPS else 0  # non-zero aborts the query

    connection.set_progress_handler(progress, _PROGRESS_EVERY)


def _check_schema(connection: sqlite3.Connection) -> None:
    tables = {
        name
        for (name,) in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN "
            "('session', 'message', 'part')"
        )
    }
    for table, needed in _COLUMNS.items():
        if table not in tables:
            raise ValueError(f"unsupported OpenCode database schema: no {table} table")
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        if missing := needed - columns:
            raise ValueError(
                f"unsupported OpenCode database schema: {table} lacks {', '.join(sorted(missing))}"
            )


def root_sessions(connection: sqlite3.Connection, limit: int) -> list[tuple[str, int, int]]:
    """``(id, time_updated ms, message count)`` of top-level sessions, newest first."""
    rows = connection.execute(
        "SELECT s.id, s.time_updated, (SELECT COUNT(*) FROM message m WHERE m.session_id = s.id) "
        "FROM session s WHERE s.parent_id IS NULL ORDER BY s.time_updated DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [(str(row[0]), int(row[1] or 0), int(row[2] or 0)) for row in rows]


def child_sessions(connection: sqlite3.Connection, parent: str) -> list[str]:
    rows = connection.execute(
        "SELECT id FROM session WHERE parent_id = ? ORDER BY time_created, id LIMIT ?",
        (parent, MAX_SESSIONS),
    ).fetchall()
    return [str(row[0]) for row in rows]


def session_exists(connection: sqlite3.Connection, session: str) -> bool:
    row = connection.execute("SELECT 1 FROM session WHERE id = ?", (session,)).fetchone()
    return row is not None


__all__ = [
    "MAX_ROWS",
    "MAX_SESSIONS",
    "SEP",
    "child_sessions",
    "connect",
    "default_db",
    "looks_like_sqlite",
    "root_sessions",
    "session_exists",
    "split_source",
]
