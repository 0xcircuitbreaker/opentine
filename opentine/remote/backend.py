"""Encrypted filesystem objects plus SQLite metadata reference backend."""

from __future__ import annotations

import os
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from opentine._canon import _fsync_dir
from opentine.kernel import OBJECT_TYPES, ObjectEnvelope, parse_oid
from opentine.remote._audit import GENESIS, load_key, read_anchor, write_anchor
from opentine.remote._audit_backend import SQLiteAuditMixin
from opentine.remote._schema import initialize
from opentine.remote.interfaces import KeyProvider, RetentionHook

_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REF = re.compile(r"^(?:heads|tags|experiments|promotions|remotes)/[A-Za-z0-9._/-]+$")
MAX_CONTROL_RESULTS = 1000
MAX_OBJECT_LIST = 100_000


def valid_tenant(tenant: str) -> str:
    if not _TENANT.fullmatch(tenant):
        raise ValueError("invalid tenant namespace")
    return tenant


def valid_ref(name: str) -> str:
    normalized = name.removeprefix("refs/")
    parts = normalized.split("/")
    if (
        len(normalized) > 512
        or not _REF.fullmatch(normalized)
        or any(part in {"", ".", ".."} or part.endswith(".lock") for part in parts)
    ):
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
                        if len(found) > MAX_OBJECT_LIST:
                            raise ValueError(
                                "tenant object listing exceeds reference backend limit"
                            )
        return found


class SQLiteBackend(SQLiteAuditMixin):
    validate_tenant = staticmethod(valid_tenant)

    def __init__(
        self,
        path: str | Path,
        *,
        audit_key: bytes | None = None,
        migrate_legacy_audit: bool = False,
    ):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key_path = Path(str(self.path) + ".audit-key")
        self._anchor_path = Path(str(self.path) + ".audit-head")
        self._audit_key, _ = load_key(self._key_path, audit_key)
        allow_legacy = migrate_legacy_audit and not self._anchor_path.exists()
        self._initialize(allow_legacy)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self, allow_legacy: bool) -> None:
        migrated = initialize(self._connect, self._audit_key, allow_legacy=allow_legacy)
        valid, head = self._verified_head()
        if not valid:
            raise RuntimeError("audit chain verification failed")
        anchored = read_anchor(self._anchor_path, self._audit_key)
        if anchored is None:
            if head != GENESIS and not (allow_legacy or migrated):
                raise RuntimeError("audit anchor is missing; explicit recovery is required")
            write_anchor(self._anchor_path, head, self._audit_key)
        elif anchored != head:
            raise RuntimeError("audit chain does not match its authenticated anchor")

    def record_object(self, tenant: str, oid: str, size: int) -> None:
        with self._connect() as database:
            database.execute(
                "INSERT OR IGNORE INTO objects(tenant,oid,size) VALUES(?,?,?)",
                (valid_tenant(tenant), oid, size),
            )

    def list_refs(self, tenant: str) -> dict[str, str]:
        with self._connect() as database:
            rows = database.execute(
                "SELECT name,oid FROM refs WHERE tenant=? ORDER BY name LIMIT ?",
                (valid_tenant(tenant), MAX_CONTROL_RESULTS + 1),
            ).fetchall()
        if len(rows) > MAX_CONTROL_RESULTS:
            raise ValueError("ref listing exceeds control-plane result limit")
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
        if prefix and prefix not in OBJECT_TYPES:
            raise ValueError("invalid object type filter")
        with self._connect() as database:
            rows = database.execute(
                "SELECT oid FROM objects WHERE tenant=? AND oid LIKE ? "
                "ORDER BY created_at DESC LIMIT ?",
                (valid_tenant(tenant), f"{prefix}%", MAX_CONTROL_RESULTS + 1),
            ).fetchall()
        if len(rows) > MAX_CONTROL_RESULTS:
            raise ValueError("search exceeds control-plane result limit")
        return [row[0] for row in rows]
