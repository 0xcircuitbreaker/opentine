"""Bounded verified rendering for repository object inspection."""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

from opentine.kernel import parse_oid
from opentine.repository._blob_io import read_verified_blob_prefix, stored_object_size

if TYPE_CHECKING:
    from opentine.repository.store import Repo

MAX_INSPECT_BLOB_BYTES = 512 * 1024
MAX_INSPECT_SOURCE_BYTES = 256 * 1024 * 1024
MAX_INSPECT_RESOLVED_BYTES = 1024 * 1024
MAX_INSPECT_RESOLVED_BLOBS = 64
MAX_INSPECT_STRUCTURED_BYTES = 4 * 1024 * 1024


def _direct_blob(repo: Repo, oid: str) -> dict[str, Any]:
    raw, size, schema = read_verified_blob_prefix(
        repo,
        oid,
        prefix_limit=MAX_INSPECT_BLOB_BYTES,
        source_limit=MAX_INSPECT_SOURCE_BYTES,
    )
    truncated = size > len(raw)
    try:
        payload = {"encoding": "utf-8", "text": raw.decode("utf-8")}
    except UnicodeDecodeError:
        payload = {
            "data": base64.b64encode(raw).decode("ascii"),
            "encoding": "base64",
        }
    payload.update({"size_bytes": size, "truncated": truncated})
    return {"id": oid, "payload": payload, "schema": schema, "type": "blob"}


def _resolved(repo: Repo, payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    blobs: dict[str, Any] = {}
    cache: dict[str, tuple[bytes, int]] = {}
    remaining = MAX_INSPECT_RESOLVED_BYTES
    source_remaining = MAX_INSPECT_SOURCE_BYTES
    truncated = False
    count = 0
    for field, value in payload.items():
        if not (
            field.endswith("_blob")
            and isinstance(value, str)
            and parse_oid(value)[0] == "blob"
            and repo.has(value)
        ):
            continue
        if count >= MAX_INSPECT_RESOLVED_BLOBS or remaining <= 0:
            truncated = True
            break
        maximum = min(MAX_INSPECT_BLOB_BYTES, remaining)
        cached = cache.get(value)
        if cached is None:
            raw, size, _ = read_verified_blob_prefix(
                repo,
                value,
                prefix_limit=MAX_INSPECT_BLOB_BYTES,
                source_limit=source_remaining,
            )
            source_remaining -= size
            cache[value] = (raw, size)
        else:
            raw, size = cached
        raw = raw[:maximum]
        remaining -= len(raw)
        count += 1
        if size > len(raw):
            blobs[field] = {
                "encoding": "utf-8",
                "text": raw.decode(errors="replace"),
                "size_bytes": size,
                "truncated": True,
            }
            truncated = True
            continue
        try:
            blobs[field] = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            blobs[field] = raw.decode(errors="replace")
    return blobs, truncated


def inspect(repo: Repo, oid: str, *, resolve_blobs: bool = False) -> dict[str, Any]:
    object_type, _ = parse_oid(oid)
    if object_type == "blob":
        return _direct_blob(repo, oid)
    if stored_object_size(repo, oid) > MAX_INSPECT_STRUCTURED_BYTES:
        raise ValueError("structured object exceeds the 4 MiB inspection limit")
    envelope = repo.get(oid)
    payload = envelope.payload()
    result = {
        "id": oid,
        "payload": payload,
        "schema": envelope.schema,
        "type": envelope.object_type,
    }
    if resolve_blobs and isinstance(payload, dict):
        blobs, truncated = _resolved(repo, payload)
        result["resolved_blobs"] = blobs
        if truncated:
            result["resolved_blobs_truncated"] = True
    return result
