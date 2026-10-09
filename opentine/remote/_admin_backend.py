"""SQLite primitives behind the operator's offline maintenance (``_admin``)."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from sqlite3 import Connection

from opentine.remote._association_backend import _chunks


class SQLiteAdminMixin:
    @contextmanager
    def exclusive(self) -> Iterator[Connection]:
        """One write transaction: no ref update or object install commits meanwhile."""
        with self._connect() as database:
            database.execute("BEGIN IMMEDIATE")
            yield database

    def clock(self) -> str:
        """The database's ``CURRENT_TIMESTAMP``, the clock ``created_at`` is written in."""
        with self._connect() as database:
            return database.execute("SELECT CURRENT_TIMESTAMP").fetchone()[0]

    def associations_with_times(self, tenant: str, target_id: str, limit: int) -> list[tuple]:
        with self._connect() as database:
            return database.execute(
                "SELECT oid,created_at FROM objects WHERE tenant=? AND target_id=? "
                "ORDER BY created_at,oid LIMIT ?",
                (self.validate_tenant(tenant), target_id, limit),
            ).fetchall()


def ref_targets(database: Connection, tenant: str) -> dict[str, str]:
    return dict(database.execute("SELECT name,oid FROM refs WHERE tenant=?", (tenant,)))


def installed_since(database: Connection, tenant: str, since: str) -> set[str]:
    rows = database.execute(
        "SELECT oid FROM objects WHERE tenant=? AND created_at>=?", (tenant, since)
    )
    return {row[0] for row in rows}


def forget(database: Connection, tenant: str, oids: Iterable[str]) -> None:
    for chunk in _chunks(oids):
        marks = ",".join("?" * len(chunk))
        database.execute(
            f"DELETE FROM objects WHERE tenant=? AND oid IN ({marks})", (tenant, *chunk)
        )
