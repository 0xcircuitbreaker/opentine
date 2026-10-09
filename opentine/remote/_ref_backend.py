"""SQLite ref storage: CAS updates, the operator's CAS delete, and the tenant ref bound.

Every fetch and push starts with ``GET /refs``, which returns the tenant's whole
listing, and clients refuse a control response over 1 MiB. The listing was
bounded at 1000 refs -- but a push of each new run adds an ``annotations/`` ref,
so about a thousand pushed runs left a tenant whose pushes failed at that step.
The bound is now what keeps the listing readable by every client: at most
:data:`MAX_TENANT_REFS` refs and :data:`MAX_REF_LISTING_BYTES` of names and ids,
well under the 1 MiB clients accept, so a write can never leave a listing that
a client refuses. A run's annotation ref is about 160 bytes, so the byte bound
is reached only by long ref names.
"""

from __future__ import annotations

from opentine.repository._refs import normalize_ref

MAX_TENANT_REFS = 4096
#: Serialized ``{"name":"oid",...}`` bytes; clients read at most 1 MiB.
MAX_REF_LISTING_BYTES = 896 * 1024
_ENTRY_OVERHEAD = 6  # two quotes around each of name and oid, a colon, a comma


def _entry(name: str, oid: str) -> int:
    return len(name) + len(oid) + _ENTRY_OVERHEAD


class SQLiteRefMixin:
    def list_refs(self, tenant: str) -> dict[str, str]:
        with self._connect() as database:
            rows = database.execute(
                "SELECT name,oid FROM refs WHERE tenant=? ORDER BY name LIMIT ?",
                (self.validate_tenant(tenant), MAX_TENANT_REFS + 1),
            ).fetchall()
        if len(rows) > MAX_TENANT_REFS:
            raise ValueError("ref listing exceeds control-plane result limit")
        return dict(rows)

    def read_ref(self, tenant: str, name: str) -> str | None:
        with self._connect() as database:
            row = database.execute(
                "SELECT oid FROM refs WHERE tenant=? AND name=?",
                (self.validate_tenant(tenant), normalize_ref(name)),
            ).fetchone()
        return row[0] if row else None

    def update_ref(self, tenant: str, name: str, new_oid: str, expected_old: str | None) -> bool:
        tenant = self.validate_tenant(tenant)
        name = normalize_ref(name)
        with self._connect() as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT oid FROM refs WHERE tenant=? AND name=?", (tenant, name)
            ).fetchone()
            old = row[0] if row else None
            if old != expected_old:
                return False
            count, size = database.execute(
                "SELECT count(*),coalesce(sum(length(name)+length(oid)),0) FROM refs "
                "WHERE tenant=?",
                (tenant,),
            ).fetchone()
            if row is None and count >= MAX_TENANT_REFS:
                raise ValueError("tenant ref count exceeds control-plane limit")
            size += count * _ENTRY_OVERHEAD + _entry(name, new_oid)
            if old is not None:
                size -= _entry(name, old)
            if size > MAX_REF_LISTING_BYTES:
                raise ValueError("tenant ref listing exceeds its byte limit")
            database.execute(
                "INSERT INTO refs(tenant,name,oid) VALUES(?,?,?) "
                "ON CONFLICT(tenant,name) DO UPDATE SET "
                "oid=excluded.oid,updated_at=CURRENT_TIMESTAMP",
                (tenant, name, new_oid),
            )
        return True

    def delete_ref(self, tenant: str, name: str, expected_old: str | None) -> bool:
        """Remove *name* if it still targets *expected_old* (any target when None)."""
        tenant = self.validate_tenant(tenant)
        name = normalize_ref(name)
        with self._connect() as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT oid FROM refs WHERE tenant=? AND name=?", (tenant, name)
            ).fetchone()
            if row is None or (expected_old is not None and row[0] != expected_old):
                return False
            database.execute("DELETE FROM refs WHERE tenant=? AND name=?", (tenant, name))
        return True
