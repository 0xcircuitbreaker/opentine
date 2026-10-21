"""``tine archive``: a whole repository as one compressed file, and back.

An archive is ``b"TINEARC1\\n"`` followed by three length-prefixed parts: a
canonical JSON manifest (refs, shallow boundaries and the unadopted-annotation
record), a pack index and the
pack itself (the ``.tidx``/``.tpk`` pair ``tine gc`` writes). Every piece of
repository state that changes what a run means travels with it: a restore that
dropped the unadopted record would let a planted annotation be adopted. Caches
(indexes) are rebuilt, and the reflog is history, not state. Restoring checks
the pack's digest and every object's id, then sets each ref through the normal
validated path, so an archive cannot install anything a fetch could not.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from opentine import _codec
from opentine.kernel import KernelError, canonical_json
from opentine.repository._gc import GC_LEVEL
from opentine.repository._pack_write import build_pack, verify_packs
from opentine.repository._packs import oid_of
from opentine.repository._paths import atomic_bytes, internal_path
from opentine.repository._shallow import encode_shallow
from opentine.repository._unadopted import MAX_UNADOPTED, read_unadopted, record_unadopted

MAGIC = b"TINEARC1\n"
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024


def _uvarint(value: int) -> bytes:
    return _codec._uvarint(value)


def create_archive(repo, output: str | Path, *, codec: str | None = None) -> dict:
    chosen = codec or _codec.default_codec()
    objects = []
    for oid in repo.iter_oids():
        raw = repo.raw(oid)
        if oid_of(raw) != oid:
            raise KernelError(f"refusing to archive a corrupt object: {oid}")
        objects.append((oid, raw))
    unadopted = read_unadopted(repo.path)
    if not unadopted.complete:
        raise KernelError("refusing to archive: the unadopted annotation record is damaged")
    digest, body, index = build_pack(objects, chosen, GC_LEVEL if chosen == "zstd" else 9)
    manifest = canonical_json(
        {
            "objects": len(objects),
            "pack": digest,
            "refs": repo.list_refs(),
            "shallow": sorted(repo.shallow_oids()),
            "unadopted": sorted(unadopted),
            "version": 1,
        }
    )
    data = MAGIC
    for part in (manifest, index, body):
        data += _uvarint(len(part)) + part
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_bytes(target, data)
    raw_total = sum(len(raw) for _, raw in objects)
    return {"objects": len(objects), "raw_bytes": raw_total, "archive_bytes": len(data)}


def _parts(data: bytes) -> tuple[bytes, bytes, bytes]:
    if not data.startswith(MAGIC):
        raise KernelError("not an opentine archive")
    cursor, parts = len(MAGIC), []
    for _ in range(3):
        size, cursor = _codec._read_uvarint(data, cursor)
        if cursor + size > len(data):
            raise KernelError("archive is truncated")
        parts.append(data[cursor : cursor + size])
        cursor += size
    if cursor != len(data):
        raise KernelError("archive has trailing data")
    return parts[0], parts[1], parts[2]


def restore_archive(archive: str | Path, destination: str | Path) -> dict:
    """Restore *archive* into a new repository at *destination*."""
    from opentine.repository.store import Repo

    source = Path(archive)
    if source.stat().st_size > MAX_ARCHIVE_BYTES:
        raise KernelError("archive exceeds the restore size limit")
    manifest_raw, index, body = _parts(source.read_bytes())
    if len(manifest_raw) > MAX_MANIFEST_BYTES:
        raise KernelError("archive manifest exceeds its size limit")
    try:
        manifest = json.loads(manifest_raw)
    except (ValueError, RecursionError) as exc:
        raise KernelError("archive manifest is malformed") from exc
    if not isinstance(manifest, dict) or manifest.get("version") != 1:
        raise KernelError("archive manifest is not a supported version")
    digest = hashlib.sha256(body).hexdigest()
    if manifest.get("pack") != digest:
        raise KernelError("archive pack does not match its manifest")
    target = Path(destination).expanduser()
    tine = target if target.name == ".tine" else target / ".tine"
    if (tine / "config.json").exists():
        existing = Repo(tine)
        if existing.iter_oids(limit=1, truncate=True) or existing.list_refs():
            raise KernelError("restore target already holds a repository")
    repo = Repo.init(tine.parent)
    atomic_bytes(internal_path(repo.path, "packs", f"{digest}.tpk"), body)
    atomic_bytes(internal_path(repo.path, "packs", f"{digest}.tidx"), index)
    errors = verify_packs(repo.path)
    if errors:
        for suffix in (".tidx", ".tpk"):
            internal_path(repo.path, "packs", digest + suffix).unlink(missing_ok=True)
        raise KernelError(f"archive pack failed verification: {errors[0]}")
    shallow = manifest.get("shallow") or []
    if shallow:
        atomic_bytes(internal_path(repo.path, "shallow"), encode_shallow(set(shallow)))
        repo._invalidate_shallow()
    unadopted = manifest.get("unadopted") or []
    if not isinstance(unadopted, list) or len(unadopted) > MAX_UNADOPTED:
        raise KernelError("archive unadopted record is malformed")
    if unadopted:
        if not all(isinstance(oid, str) and oid.startswith("annotation:") for oid in unadopted):
            raise KernelError("archive unadopted record lists a non-annotation")
        if record_unadopted(repo.path, unadopted):
            raise KernelError("archive unadopted record does not fit")
        if read_unadopted(repo.path, strict=True) != frozenset(unadopted):
            raise KernelError("archive unadopted record did not restore intact")
    from opentine.repository._gc import enable_storage

    enable_storage(repo, repo._storage_codec or _codec.default_codec())
    refs = manifest.get("refs") or {}
    if not isinstance(refs, dict):
        raise KernelError("archive refs are malformed")
    for name, oid in sorted(refs.items()):
        repo.update_ref(name, oid, actor="archive")
    return {"objects": int(manifest.get("objects") or 0), "refs": len(refs), "path": str(repo.path)}
