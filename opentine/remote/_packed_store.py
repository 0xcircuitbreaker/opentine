"""An ``ObjectStore`` of packs on object storage (0.77): ``TINE_REMOTE_PACK_STORE``.

Every write (a pushed pack, an ingest batch) lands as **one** pack: the
local pack format (``TINELP1``, :mod:`opentine.repository._pack_write`),
sealed per tenant, under :class:`~opentine.remote._pack_blobs.PackBlobs`::

    <tenant>/packs/<sha256>.tpk    sealed pack body (named by the plain body's digest)
    <tenant>/packs/<sha256>.tidx   sealed u64 body size + pack index; written last

The index is written after the body, so a listed index whose body is not
there yet (a listing race, or a compaction deleting it) is skipped and looked
for again on the next miss. A body is checked against its name's SHA-256 when
it is read, and every object against its id, so a wrong index or a swapped
body fails closed. Names are never overwritten. ``delete`` rewrites every
pack holding the object without it (a new name), then removes the old index
and body; two replicas racing on one put can store an object twice, and no
copy may survive a purge.
Push, pull, the purge graph and :meth:`fsck` read through the same index.
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from opentine import _codec
from opentine.kernel import KernelError, ObjectEnvelope
from opentine.remote._sealed import seal, storage_codec, unseal
from opentine.remote.backend import valid_tenant
from opentine.repository._pack_index import PACK_MAGIC, _parse_index
from opentine.repository._pack_write import build_pack

BODY, INDEX = "pack", "pack-index"
_CACHED_BODIES = 4


class PackedObjectStore:
    def __init__(self, blobs: Any, keys: Any, *, holds_root: str | Path | None = None,
                 codec: str | None = "default"):  # fmt: skip
        self.blobs, self.keys = blobs, keys
        self.root = Path(holds_root) if holds_root is not None else None
        self.codec = storage_codec(codec) or "none"
        self._where: dict[str, dict[str, tuple[str, int, int, int]]] = {}
        self._blocks: dict[str, dict[str, list]] = {}
        self._bodies: OrderedDict[tuple[str, str], bytes] = OrderedDict()
        self._lock = threading.RLock()  # tine serve answers requests on many threads

    # -- index -----------------------------------------------------------
    def _name(self, tenant: str, digest: str, suffix: str) -> str:
        return f"{valid_tenant(tenant)}/packs/{digest}.{suffix}"

    def _index(self, tenant: str, digest: str) -> tuple[list, dict[str, tuple[int, int, int]]]:
        sealed = self.blobs.get(self._name(tenant, digest, "tidx"))
        plain = unseal(self.keys, INDEX, tenant, digest, sealed)
        return _parse_index(plain[8:], digest, int.from_bytes(plain[:8], "big"))

    def _load(self, tenant: str, digest: str) -> bool:
        try:
            blocks, entries = self._index(tenant, digest)
        except Exception:  # noqa: BLE001 - missing or unreadable: skipped, fsck reports it
            return False
        if not self.blobs.exists(self._name(tenant, digest, "tpk")):
            return False  # a listing race: the body is not there (yet, or any more)
        where = self._where.setdefault(tenant, {})
        self._blocks.setdefault(tenant, {})[digest] = blocks
        for oid, (block, start, length) in entries.items():
            where.setdefault(oid, (digest, block, start, length))
        return True

    def _listed(self, tenant: str) -> list[str]:
        names = self.blobs.names(f"{valid_tenant(tenant)}/packs/")
        return [n.rsplit("/", 1)[1][:-5] for n in names if n.endswith(".tidx")]

    def refresh(self, tenant: str) -> None:
        with self._lock:
            known = self._blocks.setdefault(tenant, {})
            listed = set(self._listed(tenant))
            for digest in sorted(listed - set(known)):
                self._load(tenant, digest)
            for digest in set(known) - listed:  # removed by a delete or compaction
                known.pop(digest)
                where = self._where.get(tenant, {})
                for oid in [o for o, place in where.items() if place[0] == digest]:
                    where.pop(oid)

    def _locate(self, tenant: str, oid: str) -> tuple[str, int, int, int] | None:
        place = self._where.get(tenant, {}).get(oid)
        if place is None:
            self.refresh(tenant)
            place = self._where.get(tenant, {}).get(oid)
        return place

    def _body(self, tenant: str, digest: str) -> bytes:
        with self._lock:
            key = (tenant, digest)
            if key not in self._bodies:
                sealed = self.blobs.get(self._name(tenant, digest, "tpk"))
                body = unseal(self.keys, BODY, tenant, digest, sealed)
                if hashlib.sha256(body).hexdigest() != digest or not body.startswith(PACK_MAGIC):
                    raise KernelError(f"pack {digest} does not match its name")
                self._bodies[key] = body
                while len(self._bodies) > _CACHED_BODIES:
                    self._bodies.popitem(last=False)
            self._bodies.move_to_end(key)
            return self._bodies[key]

    # -- ObjectStore -----------------------------------------------------
    def has(self, tenant: str, oid: str) -> bool:
        return self._locate(tenant, oid) is not None

    def size(self, tenant: str, oid: str) -> int:
        place = self._locate(tenant, oid)
        if place is None:
            raise KeyError(oid)
        return place[3]

    def get(self, tenant: str, oid: str) -> bytes:
        place = self._locate(tenant, oid)
        if place is None:
            raise KeyError(oid)
        digest, number, start, length = place
        try:
            body = self._body(tenant, digest)
        except KeyError:  # deleted under us: read the rewritten pack once
            self.refresh(tenant)
            moved = self._locate(tenant, oid)
            if moved is None or moved == place:
                raise
            return self.get(tenant, oid)
        offset, stored_length, size = self._blocks[tenant][digest][number]
        block = _codec.unwrap(body[offset : offset + stored_length], limit=size)
        raw = block[start : start + length]
        ObjectEnvelope.decode(raw, oid)
        return raw

    def put(self, tenant: str, oid: str, data: bytes) -> None:
        self.put_many(tenant, [(oid, data)])

    def put_many(self, tenant: str, items: list[tuple[str, bytes]]) -> str | None:
        """Store *items* as one pack (one durability point); the pack digest, if any."""
        with self._lock:
            fresh: dict[str, bytes] = {}
            for oid, data in items:
                ObjectEnvelope.decode(data, oid)
                if self.has(tenant, oid):
                    if self.get(tenant, oid) != data:
                        raise ValueError("object id collision")
                    continue
                fresh[oid] = data
            if not fresh:
                return None
            digest, body, index = build_pack(sorted(fresh.items()), self.codec, None)
            sized = len(body).to_bytes(8, "big") + index
            self.blobs.put(
                self._name(tenant, digest, "tpk"), seal(self.keys, BODY, tenant, digest, body)
            )
            if not self.blobs.put(self._name(tenant, digest, "tidx"),
                                  seal(self.keys, INDEX, tenant, digest, sized)):  # fmt: skip
                self._body(tenant, digest)  # same name: the stored body must be this content
            if not self._load(tenant, digest):
                raise KernelError(f"pack {digest} is not readable after it was written")
            return digest

    def list(self, tenant: str, *, limit: int | None = None, truncate: bool = False) -> list[str]:
        self.refresh(tenant)
        oids = sorted(self._where.get(tenant, {}))
        if limit is not None and len(oids) > limit and not truncate:
            raise ValueError(f"more than {limit} objects")
        return oids[:limit] if limit is not None else oids

    def iter(self, tenant: str) -> Iterator[str]:
        return iter(self.list(tenant))

    def held(self, tenant: str) -> set[str]:
        from opentine.repository._holds import held_oids

        if self.root is None:
            return set()
        return held_oids(self.root / ".holds" / valid_tenant(tenant))

    def tombstoned(self, tenant: str, oid: str) -> bool:
        from opentine.remote._tombstone_store import has

        return self.root is not None and has(self.root, tenant, oid)

    def delete(self, tenant: str, oid: str) -> None:
        """Rewrite *every* pack holding *oid* without it: a put race between replicas
        can store an object twice, and a copy left behind would come back on restart."""
        with self._lock:
            if oid in self.held(tenant):
                raise PermissionError(f"{oid} is held")
            found = False
            for digest in sorted(self._listed(tenant)):
                try:
                    blocks, entries = self._index(tenant, digest)
                except Exception:  # noqa: BLE001 - unreadable: fsck reports it
                    continue
                if oid in entries:
                    found = True
                    self._drop(tenant, oid, digest, blocks, entries)
            if not found:
                raise FileNotFoundError(oid)

    def _drop(self, tenant: str, oid: str, digest: str, blocks: list, entries: dict) -> None:
        body = self._body(tenant, digest)
        keep = []
        for other, (number, start, length) in sorted(entries.items()):
            if other != oid:
                offset, stored_length, size = blocks[number]
                block = _codec.unwrap(body[offset : offset + stored_length], limit=size)
                ObjectEnvelope.decode(block[start : start + length], other)
                keep.append((other, block[start : start + length]))
        where = self._where.get(tenant, {})
        self._where[tenant] = {o: p for o, p in where.items() if p[0] != digest and o != oid}
        if keep:
            self.put_many(tenant, keep)  # durable under its new name before the old goes
        self.blobs.delete(self._name(tenant, digest, "tidx"))
        self.blobs.delete(self._name(tenant, digest, "tpk"))
        self._blocks.get(tenant, {}).pop(digest, None)
        self._bodies.pop((tenant, digest), None)

    def fsck(self, tenant: str) -> dict[str, Any]:
        """Re-read every pack and object of *tenant*: ``{"packs", "objects", "bad"}``."""
        self.refresh(tenant)
        bad: list[str] = []
        for oid in sorted(self._where.get(tenant, {})):
            try:
                self.get(tenant, oid)
            except Exception as exc:  # noqa: BLE001 - every unreadable object is reported
                bad.append(f"{oid}: {exc}")
        for digest in self._listed(tenant):
            if digest not in self._blocks.get(tenant, {}):
                bad.append(f"pack {digest}: index without a readable body")
        return {"tenant": tenant, "packs": len(self._blocks.get(tenant, {})),
                "objects": len(self._where.get(tenant, {})), "bad": bad}  # fmt: skip


__all__ = ["PackedObjectStore"]
