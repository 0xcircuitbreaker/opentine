"""SQLite reverse association index for bounded pack negotiation."""

from __future__ import annotations

from opentine.kernel import parse_oid


class SQLiteAssociationMixin:
    def record_object(self, tenant: str, oid: str, size: int, target_id: str | None = None) -> None:
        object_type, _ = parse_oid(oid)
        with self._connect() as database:
            database.execute(
                "INSERT INTO objects(tenant,oid,size,object_type,target_id) VALUES(?,?,?,?,?) "
                "ON CONFLICT(tenant,oid) DO UPDATE SET "
                "target_id=COALESCE(objects.target_id,excluded.target_id)",
                (self.validate_tenant(tenant), oid, size, object_type, target_id),
            )

    def associated_objects(self, tenant: str, target_id: str, limit: int) -> list[str]:
        if type(limit) is not int or limit < 0:
            raise ValueError("association result limit must be non-negative")
        with self._connect() as database:
            rows = database.execute(
                "SELECT oid FROM objects WHERE tenant=? AND target_id=? ORDER BY oid LIMIT ?",
                (self.validate_tenant(tenant), target_id, limit + 1),
            ).fetchall()
        if len(rows) > limit:
            raise ValueError("association result exceeds pack object limit")
        return [row[0] for row in rows]
