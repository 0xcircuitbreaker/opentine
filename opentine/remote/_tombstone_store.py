"""A remote's tombstones: ``<objects root>/.tombstones/<tenant>/<blob hex>.json`` (0.46).

Beside ``.holds``, outside every tenant's object tree (no tenant name starts
with ``.``). One canonical-JSON ``opentine.tombstone`` per purged blob, stored
exactly as a client signed it: the server checks its shape, never signs one and
cannot check an HMAC signature (it never holds a user's key). A tombstoned oid
counts as a resolved link for the tenant (``TenantRepo._link_exists``), so
events that link a purged blob still install and serve; the blob itself is a
shallow boundary of every pack the server builds.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from opentine._signed_record import BLOB_OID
from opentine._tombstone import well_formed
from opentine.kernel import canonical_json, parse_oid
from opentine.remote.backend import valid_tenant

MAX_BYTES = 64 * 1024


def _path(root: Path, tenant: str, oid: str) -> Path:
    if not BLOB_OID.fullmatch(oid):
        raise ValueError("a tombstone names a blob oid")
    return Path(root) / ".tombstones" / valid_tenant(tenant) / f"{parse_oid(oid)[1]}.json"


def has(root: Path, tenant: str, oid: str) -> bool:
    try:
        return _path(root, tenant, oid).is_file()
    except ValueError:
        return False


def read(root: Path, tenant: str, oid: str) -> dict[str, Any] | None:
    try:
        raw = _path(root, tenant, oid).read_bytes()
    except (FileNotFoundError, ValueError):
        return None
    if len(raw) > MAX_BYTES:
        return None
    return well_formed(json.loads(raw))


def write(root: Path, tenant: str, record: dict[str, Any]) -> bool:
    """Store *record*; ``False`` when the tenant already holds a tombstone for its oid."""
    well_formed(record)
    path = _path(root, tenant, record["oid"])
    if path.exists():
        return False
    data = canonical_json(record)
    if len(data) > MAX_BYTES:
        raise ValueError("tombstone exceeds its size limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return True


def remove(root: Path, tenant: str, oid: str) -> None:
    _path(root, tenant, oid).unlink(missing_ok=True)


def tombstoned(objects: Any, tenant: str, oid: str) -> bool:
    """Whether *objects* (any ``ObjectStore``) records a tombstone for *oid*."""
    check = getattr(objects, "tombstoned", None)
    return bool(callable(check) and check(tenant, oid))


__all__ = ["has", "read", "remove", "tombstoned", "write"]
