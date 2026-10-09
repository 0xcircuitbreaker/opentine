"""SQLite reverse association index for bounded pack negotiation."""

from __future__ import annotations

from collections.abc import Iterable

from opentine.kernel import parse_oid

#: Below SQLite's oldest bound-parameter ceiling (999), with room for the tenant.
_CHUNK = 500


def _chunks(values: Iterable[str]) -> Iterable[list[str]]:
    ordered = sorted(set(values))
    for start in range(0, len(ordered), _CHUNK):
        yield ordered[start : start + _CHUNK]


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

    def recorded_targets(self, tenant: str, oids: Iterable[str]) -> dict[str, str]:
        """The ``target_id`` each installed annotation/attestation was verified with."""
        tenant = self.validate_tenant(tenant)
        found: dict[str, str] = {}
        with self._connect() as database:
            for chunk in _chunks(oids):
                marks = ",".join("?" * len(chunk))
                rows = database.execute(
                    "SELECT oid,target_id FROM objects WHERE tenant=? "
                    f"AND target_id IS NOT NULL AND oid IN ({marks})",
                    (tenant, *chunk),
                ).fetchall()
                found.update((oid, target) for oid, target in rows if isinstance(target, str))
        return found

    def association_counts(self, tenant: str, targets: Iterable[str]) -> dict[str, int]:
        """How many installed objects already target each of *targets*."""
        tenant = self.validate_tenant(tenant)
        counts: dict[str, int] = {}
        with self._connect() as database:
            for chunk in _chunks(targets):
                counts.update(dict.fromkeys(chunk, 0))
                marks = ",".join("?" * len(chunk))
                counts.update(
                    database.execute(
                        "SELECT target_id,count(*) FROM objects WHERE tenant=? "
                        f"AND target_id IN ({marks}) GROUP BY target_id",
                        (tenant, *chunk),
                    ).fetchall()
                )
        return counts
