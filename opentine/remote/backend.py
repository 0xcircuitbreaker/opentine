"""Encrypted filesystem objects plus SQLite metadata reference backend."""

from __future__ import annotations

import os
import re
import sqlite3
import tempfile
import threading
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from opentine._canon import _fsync_dir
from opentine.kernel import OBJECT_TYPES, ObjectEnvelope, parse_oid
from opentine.remote._association_backend import SQLiteAssociationMixin
from opentine.remote._audit import GENESIS, audit_file_lock, load_key, read_anchor, write_anchor
from opentine.remote._audit_backend import SQLiteAuditMixin
from opentine.remote._db import open_db
from opentine.remote._object_file import object_file_size, read_object_file
from opentine.remote._object_list import list_objects
from opentine.remote._schema import initialize
from opentine.remote.interfaces import KeyProvider, RetentionHook
from opentine.repository._refs import normalize_ref

_TENANT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_WINDOWS_NAMES = {"con", "prn", "aux", "nul"} | {
    f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10)
}
MAX_CONTROL_RESULTS = 1000


def valid_tenant(tenant: str) -> str:
    if (
        not _TENANT.fullmatch(tenant)
        or tenant.endswith(".")
        or tenant.split(".", 1)[0] in _WINDOWS_NAMES
    ):
        raise ValueError("invalid tenant namespace")
    return tenant


def valid_ref(name: str) -> str:
    return normalize_ref(name)


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
            object_file_size(self._path(tenant, oid))
        except (FileNotFoundError, ValueError):
            return False
        return True

    def size(self, tenant: str, oid: str) -> int:
        try:
            return object_file_size(self._path(tenant, oid))
        except FileNotFoundError as exc:
            raise KeyError(oid) from exc

    def get(self, tenant: str, oid: str) -> bytes:
        try:
            encrypted = read_object_file(self._path(tenant, oid))
        except FileNotFoundError as exc:
            raise KeyError(oid) from exc
        raw = self.keys.decrypt(tenant, encrypted)
        ObjectEnvelope.decode(raw, oid)
        return raw

    def put(self, tenant: str, oid: str, data: bytes) -> None:
        ObjectEnvelope.decode(data, oid)
        path = self._path(tenant, oid)
        try:
            existing = self.get(tenant, oid)
        except KeyError:
            existing = None
        if existing is not None:
            if existing != data:
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

    def list(self, tenant: str, *, limit: int | None = None, truncate: bool = False) -> list[str]:
        root = self.root / valid_tenant(tenant)
        return list_objects(root, limit=limit, truncate=truncate)


_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class SQLiteBackend(SQLiteAssociationMixin, SQLiteAuditMixin):
    validate_tenant = staticmethod(valid_tenant)

    def __init__(
        self,
        path: str | Path,
        *,
        audit_key: bytes | None = None,
        migrate_legacy_audit: bool = False,
        reanchor_audit_head: str | None = None,
    ):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Create the database privately before sqlite3 can: chmod-after-connect
        # left a window to open the file and keep a descriptor chmod cannot revoke.
        try:
            os.close(os.open(self.path, os.O_CREAT | os.O_RDWR | _NOFOLLOW, 0o600))
        except OSError:
            pass
        self._key_path = Path(str(self.path) + ".audit-key")
        self._anchor_path = Path(str(self.path) + ".audit-head")
        self._audit_lock_path = Path(str(self.path) + ".audit-lock")
        self._audit_key, _ = load_key(self._key_path, audit_key)
        self._audit_lock = threading.Lock()
        if reanchor_audit_head is not None and not re.fullmatch(
            r"[0-9a-f]{64}", reanchor_audit_head
        ):
            raise ValueError("re-anchor head must be a lowercase SHA-256 digest")
        allow_legacy = migrate_legacy_audit and not self._anchor_path.exists()
        self._initialize(allow_legacy, reanchor_audit_head)

    def _connect(self) -> AbstractContextManager[sqlite3.Connection]:
        # open_db closes the handle on exit; sqlite3's own context manager only
        # commits, and a leaked WAL handle locks the file on Windows.
        return open_db(self.path)

    def _initialize(self, allow_legacy: bool, reanchor: str | None) -> None:
        with self._audit_lock, audit_file_lock(self._audit_lock_path):
            self._initialize_locked(allow_legacy, reanchor)

    def _initialize_locked(self, allow_legacy: bool, reanchor: str | None) -> None:
        migrated = initialize(self._connect, self._audit_key, allow_legacy=allow_legacy)
        valid, head = self._verified_head()
        if not valid:
            raise RuntimeError("audit chain verification failed")
        try:
            anchored = read_anchor(self._anchor_path, self._audit_key)
        except RuntimeError:
            if reanchor != head:
                raise
            anchored = None
        if anchored is None:
            if head != GENESIS and not (migrated or reanchor == head):
                raise RuntimeError("audit anchor is missing; explicit recovery is required")
            write_anchor(self._anchor_path, head, self._audit_key)
        elif anchored != head:
            with self._connect() as database:
                last = database.execute(
                    "SELECT prev_hash FROM audit ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
            if last and anchored == last[0]:
                write_anchor(self._anchor_path, head, self._audit_key)
            elif reanchor == head:
                write_anchor(self._anchor_path, head, self._audit_key)
            else:
                raise RuntimeError("audit chain does not match its authenticated anchor")

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
            count = database.execute(
                "SELECT count(*) FROM refs WHERE tenant=?", (tenant,)
            ).fetchone()[0]
            if row is None and count >= MAX_CONTROL_RESULTS:
                raise ValueError("tenant ref count exceeds control-plane limit")
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
