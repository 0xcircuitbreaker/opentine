"""SQLite schema creation and pre-hash-chain audit migration."""

from __future__ import annotations

from collections.abc import Callable
from sqlite3 import Connection

from opentine.remote._audit import FIELDS, GENESIS, chain

SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (
  tenant TEXT NOT NULL, oid TEXT NOT NULL, size INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant, oid));
CREATE TABLE IF NOT EXISTS refs (
  tenant TEXT NOT NULL, name TEXT NOT NULL, oid TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant, name));
CREATE TABLE IF NOT EXISTS audit (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
  timestamp TEXT NOT NULL, tenant TEXT NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, outcome TEXT NOT NULL, details TEXT NOT NULL,
  prev_hash TEXT NOT NULL, row_hash TEXT NOT NULL);
"""

TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;
"""


def _upgrade_audit(database: Connection, columns: set[str]) -> None:
    if not columns:
        return
    hashes_present = {"prev_hash", "row_hash"} <= columns
    if hashes_present:
        incomplete = database.execute(
            "SELECT 1 FROM audit WHERE prev_hash IS NULL OR row_hash IS NULL LIMIT 1"
        ).fetchone()
        if not incomplete:
            return
    database.executescript(
        "DROP TRIGGER IF EXISTS audit_no_update; DROP TRIGGER IF EXISTS audit_no_delete;"
    )
    if "prev_hash" not in columns:
        database.execute("ALTER TABLE audit ADD COLUMN prev_hash TEXT")
    if "row_hash" not in columns:
        database.execute("ALTER TABLE audit ADD COLUMN row_hash TEXT")
    selected = "sequence," + ",".join(FIELDS)
    rows = database.execute(f"SELECT {selected} FROM audit ORDER BY sequence").fetchall()
    previous = GENESIS
    for record in rows:
        row = dict(zip(FIELDS, record[1:]))
        current = chain(previous, row)
        database.execute(
            "UPDATE audit SET prev_hash=?,row_hash=? WHERE sequence=?",
            (previous, current, record[0]),
        )
        previous = current


def initialize(connect: Callable[[], Connection]) -> None:
    with connect() as database:
        columns = {row[1] for row in database.execute("PRAGMA table_info(audit)")}
        _upgrade_audit(database, columns)
        database.executescript(SCHEMA)
        database.executescript(TRIGGERS)
