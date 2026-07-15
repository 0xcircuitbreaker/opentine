"""SQLite schema creation and pre-hash-chain audit migration."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
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


def _rows(database: Connection) -> list[tuple]:
    selected = "sequence," + ",".join(FIELDS) + ",prev_hash,row_hash"
    return database.execute(f"SELECT {selected} FROM audit ORDER BY sequence").fetchall()


def _valid_keyed(rows: list[tuple], key: bytes) -> bool:
    previous = GENESIS
    for record in rows:
        row = dict(zip(FIELDS, record[1:-2]))
        if record[-2] != previous or chain(previous, row, key) != record[-1]:
            return False
        previous = record[-1]
    return True


def _upgrade_audit(database: Connection, columns: set[str], key: bytes, allow_legacy: bool) -> bool:
    if not columns:
        return False
    hashes_present = {"prev_hash", "row_hash"} <= columns
    if hashes_present:
        incomplete = database.execute(
            "SELECT 1 FROM audit WHERE prev_hash IS NULL OR row_hash IS NULL LIMIT 1"
        ).fetchone()
        if not incomplete and _valid_keyed(_rows(database), key):
            return False
    count = database.execute("SELECT count(*) FROM audit").fetchone()[0]
    if count and not allow_legacy:
        raise RuntimeError(
            "audit chain verification failed; legacy rows require explicit migration "
            "with a trusted database"
        )
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
        current = chain(previous, row, key)
        database.execute(
            "UPDATE audit SET prev_hash=?,row_hash=? WHERE sequence=?",
            (previous, current, record[0]),
        )
        previous = current
    if rows:
        marker = {
            "action": "audit_migration",
            "actor": "opentine",
            "details": json.dumps(
                {"legacy_rows": len(rows), "verification": "unverified"},
                sort_keys=True,
                separators=(",", ":"),
            ),
            "event_id": "audit-migration-hmac-v2",
            "outcome": "warning",
            "tenant": "system",
            "timestamp": datetime.now(UTC).isoformat(),
        }
        current = chain(previous, marker, key)
        columns_sql = ",".join(FIELDS)
        placeholders = ",".join("?" * (len(FIELDS) + 2))
        database.execute(
            f"INSERT INTO audit({columns_sql},prev_hash,row_hash) VALUES({placeholders})",
            [marker[field] for field in FIELDS] + [previous, current],
        )
    return bool(rows)


def initialize(
    connect: Callable[[], Connection], key: bytes, *, allow_legacy: bool = False
) -> bool:
    with connect() as database:
        columns = {row[1] for row in database.execute("PRAGMA table_info(audit)")}
        migrated = _upgrade_audit(database, columns, key, allow_legacy)
        database.executescript(SCHEMA)
        database.executescript(TRIGGERS)
    return migrated
