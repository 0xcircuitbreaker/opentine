"""Keyed audit-log operations mixed into the SQLite metadata backend."""

from __future__ import annotations

import json

from opentine.remote._audit import FIELDS, GENESIS, chain, read_anchor, write_anchor
from opentine.remote.interfaces import AuditEvent

_LAST_ROW_HASH = "SELECT row_hash FROM audit ORDER BY sequence DESC LIMIT 1"


class SQLiteAuditMixin:
    def append(self, event: AuditEvent) -> None:
        row = {
            "action": event.action,
            "actor": event.actor,
            "details": json.dumps(event.details, sort_keys=True, separators=(",", ":")),
            "event_id": event.event_id,
            "outcome": event.outcome,
            "tenant": self.validate_tenant(event.tenant),
            "timestamp": event.timestamp,
        }
        with self._connect() as database:
            database.execute("BEGIN IMMEDIATE")
            last = database.execute(_LAST_ROW_HASH).fetchone()
            previous = last[0] if last else GENESIS
            if read_anchor(self._anchor_path, self._audit_key) != previous:
                raise RuntimeError("audit chain does not match its authenticated anchor")
            columns = ",".join(FIELDS)
            placeholders = ",".join("?" * (len(FIELDS) + 2))
            current = chain(previous, row, self._audit_key)
            database.execute(
                f"INSERT INTO audit({columns},prev_hash,row_hash) VALUES({placeholders})",
                [row[field] for field in FIELDS] + [previous, current],
            )
            write_anchor(self._anchor_path, current, self._audit_key)

    def audit_head(self) -> str:
        with self._connect() as database:
            last = database.execute(_LAST_ROW_HASH).fetchone()
        return last[0] if last else GENESIS

    def audit_warnings(self) -> list[str]:
        with self._connect() as database:
            migrated = database.execute(
                "SELECT 1 FROM audit WHERE action='audit_migration' AND outcome='warning' LIMIT 1"
            ).fetchone()
        return ["legacy audit rows were migrated without authenticity"] if migrated else []

    def _verified_head(self) -> tuple[bool, str]:
        previous = GENESIS
        with self._connect() as database:
            rows = database.execute(
                "SELECT " + ",".join(FIELDS) + ",prev_hash,row_hash FROM audit ORDER BY sequence"
            )
            for record in rows:
                row = dict(zip(FIELDS, record))
                if record[-2] != previous or chain(previous, row, self._audit_key) != record[-1]:
                    return False, previous
                previous = record[-1]
        return True, previous

    def verify_audit_chain(self, *, expected_head: str | None = None) -> bool:
        valid, head = self._verified_head()
        try:
            anchored = read_anchor(self._anchor_path, self._audit_key)
        except RuntimeError:
            return False
        return valid and anchored == head and (expected_head is None or head == expected_head)
