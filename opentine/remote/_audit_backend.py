"""Keyed audit-log operations mixed into the SQLite metadata backend."""

from __future__ import annotations

import json

from opentine.remote._audit import (
    FIELDS,
    GENESIS,
    audit_file_lock,
    chain,
    read_anchor,
    write_anchor,
)
from opentine.remote.interfaces import AuditEvent

_LAST_ROW = (
    "SELECT " + ",".join(FIELDS) + ",prev_hash,row_hash FROM audit ORDER BY sequence DESC LIMIT 1"
)


def _row(record) -> dict[str, str]:
    return dict(zip(FIELDS, record[: len(FIELDS)]))


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
        with self._audit_lock, audit_file_lock(self._audit_lock_path):
            with self._connect() as database:
                database.execute("BEGIN IMMEDIATE")
                last = database.execute(_LAST_ROW).fetchone()
                previous = last[-1] if last else GENESIS
                if last and chain(last[-2], _row(last), self._audit_key) != previous:
                    raise RuntimeError("audit chain tail failed authentication")
                valid, verified_head = self._verified_head_from(database)
                if not valid or verified_head != previous:
                    raise RuntimeError("audit chain continuity failed authentication")
                anchored = read_anchor(self._anchor_path, self._audit_key)
                if anchored != previous:
                    verified_heal = last and anchored == last[-2]
                    if verified_heal:
                        write_anchor(self._anchor_path, previous, self._audit_key)
                    else:
                        raise RuntimeError("audit chain does not match its authenticated anchor")
                columns = ",".join(FIELDS)
                placeholders = ",".join("?" * (len(FIELDS) + 2))
                current = chain(previous, row, self._audit_key)
                database.execute(
                    f"INSERT INTO audit({columns},prev_hash,row_hash) VALUES({placeholders})",
                    [row[field] for field in FIELDS] + [previous, current],
                )
            # The row is durable before the external checkpoint advances. Startup can
            # safely heal the single committed row if this write is interrupted.
            write_anchor(self._anchor_path, current, self._audit_key)

    def audit_head(self) -> str:
        with self._connect() as database:
            last = database.execute(_LAST_ROW).fetchone()
        return last[-1] if last else GENESIS

    def audit_warnings(self) -> list[str]:
        with self._connect() as database:
            migrated = database.execute(
                "SELECT 1 FROM audit WHERE action='audit_migration' AND outcome='warning' LIMIT 1"
            ).fetchone()
        return ["legacy audit rows were migrated without authenticity"] if migrated else []

    def _verified_head_from(self, database) -> tuple[bool, str]:
        previous = GENESIS
        rows = database.execute(
            "SELECT " + ",".join(FIELDS) + ",prev_hash,row_hash FROM audit ORDER BY sequence"
        )
        for record in rows:
            row = dict(zip(FIELDS, record))
            if record[-2] != previous or chain(previous, row, self._audit_key) != record[-1]:
                return False, previous
            previous = record[-1]
        return True, previous

    def _verified_head(self) -> tuple[bool, str]:
        with self._connect() as database:
            return self._verified_head_from(database)

    def audit_status(self, *, expected_head: str | None = None) -> str:
        for _ in range(2):
            try:
                before = read_anchor(self._anchor_path, self._audit_key)
            except RuntimeError:
                return "invalid"
            valid, head = self._verified_head()
            try:
                after = read_anchor(self._anchor_path, self._audit_key)
            except RuntimeError:
                return "invalid"
            if not valid:
                return "invalid"
            if before == after == head:
                return self._status_for(head, expected_head)
        with self._audit_lock, audit_file_lock(self._audit_lock_path):
            return self._audit_status(expected_head=expected_head)

    def _status_for(self, head: str, expected_head: str | None) -> str:
        if expected_head is not None and head != expected_head:
            return "invalid"
        return "legacy-unverified" if self.audit_warnings() else "verified"

    def _audit_status(self, *, expected_head: str | None = None) -> str:
        valid, head = self._verified_head()
        try:
            anchored = read_anchor(self._anchor_path, self._audit_key)
        except RuntimeError:
            return "invalid"
        if not valid or anchored != head:
            return "invalid"
        return self._status_for(head, expected_head)

    def verify_audit_chain(self, *, expected_head: str | None = None) -> bool:
        return self.audit_status(expected_head=expected_head) == "verified"
