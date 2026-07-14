"""Encrypted filesystem objects plus SQLite metadata reference backend."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from opentine._canon import _fsync_dir
from opentine.kernel import ObjectEnvelope, parse_oid, validate_links
from opentine.remote._audit import FIELDS, GENESIS, chain
from opentine.remote._schema import initialize
from opentine.remote.interfaces import AuditEvent, KeyProvider, RetentionHook

_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REF = re.compile(r"^(?:heads|tags|experiments|promotions|remotes)/[A-Za-z0-9._/-]+$")
_LAST_ROW_HASH = "SELECT row_hash FROM audit ORDER BY sequence DESC LIMIT 1"


def valid_tenant(tenant: str) -> str:
    if not _TENANT.fullmatch(tenant):
        raise ValueError("invalid tenant namespace")
    return tenant


def valid_ref(name: str) -> str:
    normalized = name.removeprefix("refs/")
    if not _REF.fullmatch(normalized) or ".." in normalized.split("/"):
        raise ValueError("invalid ref name")
    return normalized


class FilesystemObjectStore:
    def __init__(self, root: str | Path, keys: KeyProvider, retention: RetentionHook | None = None):
        self.root = Path(root).resolve()
        self.keys = keys
        self.retention = retention
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, tenant: str, oid: str) -> Path:
        object_type, digest = parse_oid(oid)
        return self.root / valid_tenant(tenant) / object_type / digest[:2] / digest[2:]

    def has(self, tenant: str, oid: str) -> bool:
        try:
            return self._path(tenant, oid).is_file()
        except ValueError:
            return False

    def get(self, tenant: str, oid: str) -> bytes:
        try:
            encrypted = self._path(tenant, oid).read_bytes()
        except FileNotFoundError as exc:
            raise KeyError(oid) from exc
        raw = self.keys.decrypt(tenant, encrypted)
        ObjectEnvelope.decode(raw, oid)
        return raw

    def put(self, tenant: str, oid: str, data: bytes) -> None:
        ObjectEnvelope.decode(data, oid)
        path = self._path(tenant, oid)
        if path.exists():
            if self.get(tenant, oid) != data:
                raise ValueError("object id collision")
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(self.keys.encrypt(tenant, data))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            _fsync_dir(path.parent)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def delete(self, tenant: str, oid: str) -> None:
        tenant = valid_tenant(tenant)
        if self.retention:
            self.retention.before_delete(tenant, oid)
        path = self._path(tenant, oid)
        path.unlink()
        _fsync_dir(path.parent)

    def list(self, tenant: str) -> list[str]:
        root = self.root / valid_tenant(tenant)
        found: list[str] = []
        if not root.exists():
            return found
        for object_type in sorted(root.iterdir()):
            if not object_type.is_dir():
                continue
            for prefix in sorted(object_type.iterdir()):
                for item in sorted(prefix.iterdir() if prefix.is_dir() else []):
                    digest = prefix.name + item.name
                    if len(digest) == 64:
                        found.append(f"{object_type.name}:sha256:{digest}")
        return found


class SQLiteBackend:
    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self) -> None:
        initialize(self._connect)

    def record_object(self, tenant: str, oid: str, size: int) -> None:
        with self._connect() as database:
            database.execute(
                "INSERT OR IGNORE INTO objects(tenant,oid,size) VALUES(?,?,?)",
                (valid_tenant(tenant), oid, size),
            )

    def list_refs(self, tenant: str) -> dict[str, str]:
        with self._connect() as database:
            rows = database.execute(
                "SELECT name,oid FROM refs WHERE tenant=? ORDER BY name", (valid_tenant(tenant),)
            )
        return dict(rows)

    def read_ref(self, tenant: str, name: str) -> str | None:
        with self._connect() as database:
            row = database.execute(
                "SELECT oid FROM refs WHERE tenant=? AND name=?",
                (valid_tenant(tenant), valid_ref(name)),
            ).fetchone()
        return row[0] if row else None

    def update_ref(self, tenant: str, name: str, new_oid: str, expected_old: str | None) -> bool:
        tenant = valid_tenant(tenant)
        name = valid_ref(name)
        with self._connect() as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT oid FROM refs WHERE tenant=? AND name=?", (tenant, name)
            ).fetchone()
            old = row[0] if row else None
            if old != expected_old:
                return False
            database.execute(
                "INSERT INTO refs(tenant,name,oid) VALUES(?,?,?) "
                "ON CONFLICT(tenant,name) DO UPDATE SET "
                "oid=excluded.oid,updated_at=CURRENT_TIMESTAMP",
                (tenant, name, new_oid),
            )
        return True

    def search(self, tenant: str, query: dict[str, Any]) -> list[str]:
        prefix = str(query.get("type") or "")
        with self._connect() as database:
            rows = database.execute(
                "SELECT oid FROM objects WHERE tenant=? AND oid LIKE ? ORDER BY created_at DESC",
                (valid_tenant(tenant), f"{prefix}%"),
            )
        return [row[0] for row in rows]

    def append(self, event: AuditEvent) -> None:
        row = {
            "action": event.action,
            "actor": event.actor,
            "details": json.dumps(event.details, sort_keys=True, separators=(",", ":")),
            "event_id": event.event_id,
            "outcome": event.outcome,
            "tenant": valid_tenant(event.tenant),
            "timestamp": event.timestamp,
        }
        with self._connect() as database:
            database.execute("BEGIN IMMEDIATE")
            last = database.execute(_LAST_ROW_HASH).fetchone()
            prev = last[0] if last else GENESIS
            columns = ",".join(FIELDS)
            placeholders = ",".join("?" * (len(FIELDS) + 2))
            database.execute(
                f"INSERT INTO audit({columns},prev_hash,row_hash) VALUES({placeholders})",
                [row[field] for field in FIELDS] + [prev, chain(prev, row)],
            )

    def audit_head(self) -> str:
        with self._connect() as database:
            last = database.execute(_LAST_ROW_HASH).fetchone()
        return last[0] if last else GENESIS

    def verify_audit_chain(self, *, expected_head: str | None = None) -> bool:
        prev = GENESIS
        with self._connect() as database:
            rows = database.execute(
                "SELECT " + ",".join(FIELDS) + ",prev_hash,row_hash FROM audit ORDER BY sequence"
            ).fetchall()
        for record in rows:
            row = dict(zip(FIELDS, record))
            if record[-2] != prev or chain(prev, row) != record[-1]:
                return False
            prev = record[-1]
        return expected_head is None or prev == expected_head


class TenantRepo:
    """Read adapter that lets pack negotiation operate over a tenant store."""

    def __init__(self, tenant: str, objects: FilesystemObjectStore):
        self.tenant = valid_tenant(tenant)
        self.objects = objects

    def has(self, oid: str) -> bool:
        return self.objects.has(self.tenant, oid)

    def raw(self, oid: str) -> bytes:
        return self.objects.get(self.tenant, oid)

    def get(self, oid: str) -> ObjectEnvelope:
        envelope = ObjectEnvelope.decode(self.raw(oid), oid)
        validate_links(envelope, self.has)
        return envelope

    def iter_oids(self) -> list[str]:
        return self.objects.list(self.tenant)
