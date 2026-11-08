"""Where a repository keeps its tombstones: ``tombstones/<blob hex>.json`` (0.46).

One file per purged blob, holding the signed ``opentine.tombstone`` record
(:mod:`opentine._tombstone`) as canonical JSON. The record is not an object: it
cannot live in the object store without an oid of its own, and the oid it
names must stay the one every event links. Packs carry objects only; a purged
blob is a shallow boundary of any pack that would have carried it, and the
tombstone travels beside the pack (``tine push`` and ``fetch`` on a remote that
lists ``caps.tombstones``, and the ``tombstones`` key of a bundle manifest).

Records written here are well formed and signed; their *trust* is checked
when they are read for it (``tine purge --list --pubkey/--key-file``), because
an imported record may be HMAC-signed under a key this repository never holds.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentine._signed_record import BLOB_OID
from opentine._tombstone import well_formed
from opentine.kernel import canonical_json, parse_oid
from opentine.repository._paths import atomic_bytes, internal_path

DIRECTORY = "tombstones"
MAX_TOMBSTONE_BYTES = 64 * 1024
MAX_CARRIED = 10_000


def path_for(repo: Any, oid: str) -> Path:
    if not BLOB_OID.fullmatch(oid):
        raise ValueError(f"only a blob can be purged: {oid}")
    return internal_path(repo.path, DIRECTORY, f"{parse_oid(oid)[1]}.json")


def read(repo: Any, oid: str) -> dict[str, Any] | None:
    """The stored tombstone of *oid*, or ``None``; a corrupt file raises ``ValueError``."""
    try:
        raw = path_for(repo, oid).read_bytes()
    except (FileNotFoundError, NotADirectoryError):
        return None
    if len(raw) > MAX_TOMBSTONE_BYTES:
        raise ValueError(f"tombstone of {oid} exceeds its size limit")
    record = well_formed(json.loads(raw))
    if record["oid"] != oid:
        raise ValueError(f"tombstone file of {oid} names {record['oid']}")
    return record


def listed(repo: Any) -> list[str]:
    """Every blob oid with a tombstone file, sorted."""
    directory = Path(repo.path) / DIRECTORY
    if not directory.is_dir():
        return []
    return sorted(
        f"blob:sha256:{path.stem}"
        for path in directory.glob("*.json")
        if BLOB_OID.fullmatch(f"blob:sha256:{path.stem}")
    )


def write(repo: Any, record: dict[str, Any]) -> bool:
    """Store a well-formed signed *record*; ``False`` when one is already stored."""
    well_formed(record)
    target = path_for(repo, record["oid"])
    if target.exists():
        return False
    data = canonical_json(record)
    if len(data) > MAX_TOMBSTONE_BYTES:
        raise ValueError("tombstone exceeds its size limit")
    atomic_bytes(target, data)
    return True


def carried(repo: Any, oids: Any) -> list[dict[str, Any]]:
    """The stored tombstones of *oids* (the shallow boundaries of a pack), sorted by oid."""
    out = []
    for oid in sorted(set(oids)):
        record = read(repo, oid) if BLOB_OID.fullmatch(oid) else None
        if record is not None:
            out.append(record)
    return out


def install(repo: Any, records: Any) -> int:
    """Store received tombstones of blobs this repository does not hold; return the count.

    A received tombstone never deletes local bytes: purging what this
    repository holds is ``tine purge``, under a key of its own.
    """
    if not isinstance(records, list) or len(records) > MAX_CARRIED:
        raise ValueError("tombstones must be a list of at most 10000 records")
    count = 0
    for record in records:
        well_formed(record)
        if not repo.has(record["oid"]) and write(repo, record):
            count += 1
    return count


__all__ = ["DIRECTORY", "carried", "install", "listed", "path_for", "read", "write"]
