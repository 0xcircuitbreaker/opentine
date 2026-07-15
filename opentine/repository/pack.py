"""Deterministic compressed v3 packs and missing-object negotiation."""

from __future__ import annotations

import base64
import hashlib
import json
import zlib
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from opentine.kernel import KernelError, ObjectEnvelope, canonical_json, parse_oid, validate_links
from opentine.repository.store import _atomic_bytes

if TYPE_CHECKING:
    from opentine.repository.store import Repo

MAGIC = b"TINEPACK3\0"
#: Caps for the compressed transfer and decompressed manifest. The manifest stores
#: object bytes as base64, so 256 MiB still permits roughly 190 MiB of raw objects.
MAX_PACK_BYTES = 256 * 1024 * 1024
MAX_PACK_BODY_BYTES = 256 * 1024 * 1024
MAX_PACK_OBJECTS = 10_000


def _bounded_decompress(data: bytes, limit: int) -> bytes:
    if type(limit) is not int or limit < 1:
        raise ValueError("pack body limit must be a positive integer")
    decompressor = zlib.decompressobj()
    body = decompressor.decompress(data, limit + 1)
    if len(body) > limit or decompressor.unconsumed_tail:
        raise KernelError("pack exceeds maximum decompressed size")
    body += decompressor.flush(limit + 1 - len(body))
    if len(body) > limit:
        raise KernelError("pack exceeds maximum decompressed size")
    if not decompressor.eof or decompressor.unused_data:
        raise KernelError("pack has truncated or trailing compressed data")
    return body


@dataclass(frozen=True)
class PackResult:
    pack_id: str
    objects: tuple[str, ...]
    bytes_written: int


def reachable(
    repo: Repo,
    wants: list[str],
    *,
    depth: int | None = None,
    include_associated: bool = True,
) -> list[str]:
    if not isinstance(wants, list) or not all(isinstance(oid, str) for oid in wants):
        raise KernelError("pack wants must be a list of object ids")
    if len(wants) > MAX_PACK_OBJECTS or (
        depth is not None and (type(depth) is not int or depth < 0)
    ):
        raise KernelError("invalid or excessive pack negotiation request")
    for oid in wants:
        parse_oid(oid)
    queue = deque((oid, 0) for oid in wants)
    seen: set[str] = set()
    while True:
        while queue:
            oid, event_depth = queue.popleft()
            if oid in seen or not repo.has(oid):
                continue
            if len(seen) >= MAX_PACK_OBJECTS:
                raise KernelError("pack graph exceeds maximum object count")
            seen.add(oid)
            envelope = repo.get(oid)
            links = list(validate_links(envelope))
            if depth is not None and envelope.object_type == "run":
                payload = envelope.payload()
                event_links = set(payload.get("events") or [])
                tips = payload.get("tips", [])
                links = [link for link in links if link not in event_links or link in tips]
            for link in links:
                next_depth = event_depth + (1 if link.startswith("event:") else 0)
                if depth is None or next_depth <= depth or not link.startswith("event:"):
                    queue.append((link, next_depth))
        if not include_associated:
            break
        associated = []
        for oid in repo.iter_oids():
            if oid in seen or not oid.startswith(("attestation:", "annotation:")):
                continue
            if repo.get(oid).payload().get("target_id") in seen:
                associated.append((oid, 0))
        if not associated:
            break
        queue.extend(associated)
    return sorted(seen)


def negotiate(
    repo: Repo, wants: list[str], haves: list[str], *, depth: int | None = None
) -> list[str]:
    if not isinstance(haves, list) or not all(isinstance(oid, str) for oid in haves):
        raise KernelError("pack haves must be a list of object ids")
    for oid in haves:
        parse_oid(oid)
    available = set(reachable(repo, wants, depth=depth))
    if len(haves) > MAX_PACK_OBJECTS:
        raise KernelError("pack negotiation has too many haves")
    possessed = set(reachable(repo, haves, include_associated=False))
    return sorted(available - possessed)


def create_pack(repo: Repo, oids: list[str], *, max_body: int = MAX_PACK_BODY_BYTES) -> bytes:
    if not isinstance(oids, list) or not all(isinstance(oid, str) for oid in oids):
        raise KernelError("pack objects must be a list of object ids")
    if type(max_body) is not int or max_body < 1 or len(oids) > MAX_PACK_OBJECTS:
        raise KernelError("invalid or excessive pack creation request")
    unique = sorted(set(oids))
    selected = set(unique)
    shallow = sorted(
        {link for oid in unique for link in validate_links(repo.get(oid)) if link not in selected}
    )
    estimated = 128 + sum(len(oid) + 4 for oid in shallow)
    entries = []
    for oid in unique:
        encoded = base64.b64encode(repo.raw(oid)).decode("ascii")
        estimated += len(encoded) + len(oid) + 32
        if estimated > max_body:
            raise KernelError("pack exceeds maximum decompressed size")
        entries.append({"data": encoded, "id": oid})
    body = canonical_json({"objects": entries, "shallow": shallow, "version": 1})
    if len(body) > max_body:
        raise KernelError("pack exceeds maximum decompressed size")
    digest = hashlib.sha256(body).digest()
    packed = MAGIC + digest + zlib.compress(body, level=9)
    if len(packed) > MAX_PACK_BYTES:
        raise KernelError("pack exceeds maximum transfer size")
    return packed


def inspect_pack(
    data: bytes,
    *,
    max_body: int = MAX_PACK_BODY_BYTES,
    max_pack: int = MAX_PACK_BYTES,
) -> tuple[str, list[tuple[str, bytes]], list[str]]:
    if len(data) > max_pack:
        raise KernelError("pack exceeds maximum transfer size")
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 32:
        raise KernelError("invalid pack header")
    expected = data[len(MAGIC) : len(MAGIC) + 32]
    try:
        body = _bounded_decompress(data[len(MAGIC) + 32 :], max_body)
    except zlib.error as exc:
        raise KernelError("invalid compressed pack") from exc
    actual = hashlib.sha256(body).digest()
    if actual != expected:
        raise KernelError("pack checksum mismatch")
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise KernelError("invalid pack manifest") from exc
    try:
        canonical = canonical_json(payload)
    except (KernelError, RecursionError) as exc:
        raise KernelError("invalid pack manifest") from exc
    if not isinstance(payload, dict) or canonical != body:
        raise KernelError("non-canonical or unsupported pack")
    if set(payload) != {"objects", "shallow", "version"} or type(payload.get("version")) is not int:
        raise KernelError("non-canonical or unsupported pack")
    if payload["version"] != 1:
        raise KernelError("non-canonical or unsupported pack")
    if not isinstance(payload.get("objects"), list) or not isinstance(payload.get("shallow"), list):
        raise KernelError("invalid pack manifest")
    if len(payload["objects"]) > MAX_PACK_OBJECTS or len(payload["shallow"]) > MAX_PACK_OBJECTS:
        raise KernelError("pack exceeds maximum object count")
    objects: list[tuple[str, bytes]] = []
    for entry in payload.get("objects") or []:
        try:
            if not isinstance(entry, dict) or set(entry) != {"data", "id"}:
                raise ValueError("invalid entry shape")
            raw = base64.b64decode(entry["data"], validate=True)
            ObjectEnvelope.decode(raw, entry["id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise KernelError("invalid packed object") from exc
        objects.append((entry["id"], raw))
    shallow = list(payload.get("shallow") or [])
    object_ids = [oid for oid, _ in objects]
    if not all(isinstance(oid, str) for oid in shallow):
        raise KernelError("invalid shallow object id")
    if len(set(object_ids)) != len(object_ids) or len(set(shallow)) != len(shallow):
        raise KernelError("pack contains duplicate object ids")
    if set(object_ids) & set(shallow):
        raise KernelError("packed objects cannot also be shallow boundaries")
    for oid in shallow:
        parse_oid(oid)
    return f"sha256:{actual.hex()}", objects, shallow


def install_pack(
    repo: Repo,
    data: bytes,
    *,
    max_body: int = MAX_PACK_BODY_BYTES,
    max_pack: int = MAX_PACK_BYTES,
) -> PackResult:
    pack_id, objects, shallow = inspect_pack(data, max_body=max_body, max_pack=max_pack)
    packed_ids = {oid for oid, _ in objects}
    for oid, raw in objects:
        envelope = ObjectEnvelope.decode(raw, oid)
        for link in validate_links(envelope):
            if link not in packed_ids and not repo.has(link) and link not in shallow:
                raise KernelError(f"pack has unresolved link: {link}")
    written = 0
    for oid, raw in objects:
        path = repo._object_path(oid)
        if not path.exists():
            _atomic_bytes(path, raw)
            written += len(raw)
    pack_path = repo.path / "packs" / f"{pack_id[7:]}.pack"
    if not pack_path.exists():
        _atomic_bytes(pack_path, data)
    shallow_path = repo.path / "shallow"
    if shallow or shallow_path.exists():
        existing = set(shallow_path.read_text().splitlines()) if shallow_path.exists() else set()
        boundaries = (existing - packed_ids) | set(shallow)
        body = ("\n".join(sorted(boundaries)) + ("\n" if boundaries else "")).encode()
        _atomic_bytes(shallow_path, body)
    return PackResult(pack_id, tuple(oid for oid, _ in objects), written)
