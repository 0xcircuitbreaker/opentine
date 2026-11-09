"""An ``ObjectStore`` on S3 Object Lock or Azure immutable blobs (0.49).

Keys, under the configured prefix::

    <tenant>/objects/<type>/<digest>   the sealed object, or MARKER + sealed manifest
    <tenant>/chunks/<sha256>           a sealed FastCDC chunk (shared within the tenant)
    <tenant>/chunked/<type>/<digest>   empty: names the chunked objects, for deletes

Objects are sealed exactly as on the filesystem store. A payload of
``CHUNK_THRESHOLD`` bytes or more is stored as FastCDC chunks plus a manifest;
``read_range`` and ``stream`` fetch only the chunks they need (lazy fetch) and
check each against its SHA-256, and ``get`` re-hashes the joined envelope
against its oid. Every key is written with the store's ``WormPolicy``.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from opentine.kernel import ObjectEnvelope, parse_oid
from opentine.remote._chunk_manifest import MARKER, Manifest, verified
from opentine.remote._fastcdc import CHUNK_THRESHOLD, DEFAULT_PARAMS, ChunkParams, chunks
from opentine.remote._sealed import OBJECT, seal, seal_object, storage_codec, unseal
from opentine.remote._worm import BlobClient, WormPolicy, stronger
from opentine.remote._worm_holds import WormHoldsMixin
from opentine.remote.backend import valid_tenant
from opentine.remote.interfaces import KeyProvider, RetentionHook

CHUNK = "cdc-chunk"


class WormObjectStore(WormHoldsMixin):
    def __init__(
        self,
        client: BlobClient,
        keys: KeyProvider,
        policy: WormPolicy | None = None,
        *,
        prefix: str = "",
        retention: RetentionHook | None = None,
        holds_root: str | Path | None = None,
        codec: str | None = "default",
        uncompressed_tenants: frozenset[str] = frozenset(),
        chunk_threshold: int = CHUNK_THRESHOLD,
        chunk_params: ChunkParams = DEFAULT_PARAMS,
    ):
        self.client, self.keys = client, keys
        self.policy = policy or WormPolicy()
        self.prefix = prefix.strip("/") + "/" if prefix.strip("/") else ""
        self.retention = retention
        self.holds_root = Path(holds_root) if holds_root is not None else None
        self.root = self.holds_root  # tombstone records live here, as for the filesystem
        self.uncompressed_tenants = uncompressed_tenants
        self.codec = storage_codec(codec)
        self.chunk_threshold, self.chunk_params = chunk_threshold, chunk_params

    # keys
    def _key(self, tenant: str, oid: str, area: str = "objects") -> str:
        object_type, digest = parse_oid(oid)
        return f"{self.prefix}{valid_tenant(tenant)}/{area}/{object_type}/{digest}"

    def _chunk_key(self, tenant: str, digest: str) -> str:
        return f"{self.prefix}{valid_tenant(tenant)}/chunks/{digest}"

    def _write(self, key: str, data: bytes, *, hold: bool = False) -> None:
        self.client.put(
            key, data, mode=self.policy.mode, until=self.policy.until(), legal_hold=hold
        )

    # ObjectStore
    def has(self, tenant: str, oid: str) -> bool:
        return self.client.exists(self._key(tenant, oid))

    def put(self, tenant: str, oid: str, data: bytes) -> None:
        ObjectEnvelope.decode(data, oid)
        try:
            existing = self.get(tenant, oid)
        except KeyError:
            existing = None
        if existing is not None:
            if existing != data:
                raise ValueError("object id collision")
            return
        if len(data) < self.chunk_threshold:
            codec = None if tenant in self.uncompressed_tenants else self.codec
            sealed = seal_object(self.keys, tenant, oid, data, codec)
            self._write(self._key(tenant, oid), sealed)
            return
        pieces = list(chunks(data, self.chunk_params))
        manifest = Manifest.of(pieces)
        until = self.policy.until()
        for (digest, _), piece in zip(manifest.chunks, pieces, strict=True):
            key = self._chunk_key(tenant, digest)
            if not self.client.exists(key):  # chunks are shared: write each once
                self._write(key, self._seal_chunk(tenant, digest, piece))
            elif self.policy.mode and until is not None:
                # a reused chunk must outlive this object's retention too
                mode = stronger(self.client.retention(key), self.policy.mode, until)
                if mode is not None:
                    self.client.extend(key, mode, until)
        self._write(self._key(tenant, oid, "chunked"), b"")
        sealed = seal(self.keys, OBJECT, tenant, oid, manifest.encode())
        self._write(self._key(tenant, oid), MARKER + sealed)  # last: readers never see half

    def _seal_chunk(self, tenant: str, digest: str, piece: bytes) -> bytes:
        sealer = getattr(self.keys, "seal_compressed", None)
        if self.codec and tenant not in self.uncompressed_tenants and callable(sealer):
            return sealer(CHUNK, tenant, digest, piece, self.codec)
        return seal(self.keys, CHUNK, tenant, digest, piece)

    def manifest(self, tenant: str, oid: str) -> Manifest | None:
        """The chunk manifest of *oid*, or None when it is stored whole."""
        stored = self._stored(tenant, oid)
        if not stored.startswith(MARKER):
            return None
        return Manifest.decode(unseal(self.keys, OBJECT, tenant, oid, stored[len(MARKER) :]))

    def _stored(self, tenant: str, oid: str) -> bytes:
        return self.client.get(self._key(tenant, oid))

    def _chunk(self, tenant: str, digest: str) -> bytes:
        sealed = self.client.get(self._chunk_key(tenant, digest))
        return verified(digest, unseal(self.keys, CHUNK, tenant, digest, sealed))

    def stream(self, tenant: str, oid: str) -> Iterator[bytes]:
        """The object's bytes in pieces, each chunk fetched only when reached."""
        stored = self._stored(tenant, oid)
        if not stored.startswith(MARKER):
            yield unseal(self.keys, OBJECT, tenant, oid, stored)
            return
        manifest = Manifest.decode(unseal(self.keys, OBJECT, tenant, oid, stored[len(MARKER) :]))
        for digest, _size in manifest.chunks:
            yield self._chunk(tenant, digest)

    def read_range(self, tenant: str, oid: str, start: int, length: int) -> bytes:
        """``length`` bytes from ``start``, fetching only the chunks that hold them.

        Each fetched chunk is checked against its digest; the whole-object hash
        is checked by ``get``, which callers use before trusting an envelope.
        """
        if start < 0 or length < 0:
            raise ValueError("range must be non-negative")
        manifest = self.manifest(tenant, oid)
        if manifest is None:
            return self.get(tenant, oid)[start : start + length]
        out = bytearray()
        for _index, digest, offset, _size in manifest.span(start, length):
            piece = self._chunk(tenant, digest)
            out += piece[max(0, start - offset) : start + length - offset]
        return bytes(out)

    def get(self, tenant: str, oid: str) -> bytes:
        raw = b"".join(self.stream(tenant, oid))
        ObjectEnvelope.decode(raw, oid)  # re-hash: chunk digests alone are not the oid
        return raw

    def size(self, tenant: str, oid: str) -> int:
        manifest = self.manifest(tenant, oid)
        return manifest.total if manifest else len(self.get(tenant, oid))

    def list(self, tenant: str, *, limit: int | None = None, truncate: bool = False) -> list[str]:
        if limit is not None and (type(limit) is not int or limit < 1):
            raise ValueError("object listing limit must be a positive integer")
        found: list[str] = []
        for oid in self.iter(tenant):
            if limit is not None and len(found) >= limit:
                if truncate:
                    break
                raise ValueError("object listing exceeds its limit")
            found.append(oid)
        return sorted(found)

    def iter(self, tenant: str) -> Iterator[str]:
        base = f"{self.prefix}{valid_tenant(tenant)}/objects/"
        for key in self.client.keys(base):
            object_type, _, digest = key[len(base) :].partition("/")
            if len(digest) == 64:
                yield f"{object_type}:sha256:{digest}"
