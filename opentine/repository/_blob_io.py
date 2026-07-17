"""Streaming verification for bounded repository blob inspection."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from opentine.kernel import KernelError, canonical_json, parse_oid

_HEADER_LIMIT = 256
_READ_CHUNK = 64 * 1024


def _open_object(repo, oid: str):
    parse_oid(oid)
    path: Path = repo._object_path(oid)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError as exc:
        raise KeyError(oid) from exc
    except OSError as exc:
        raise KernelError("repository blob cannot be safely opened") from exc
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise KernelError("repository blob is not a private regular file")
    return os.fdopen(fd, "rb"), info.st_size


def stored_object_size(repo, oid: str) -> int:
    """Return a confined regular object's encoded size without reading its body."""
    handle, size = _open_object(repo, oid)
    handle.close()
    return size


def read_verified_blob_prefix(
    repo,
    oid: str,
    *,
    prefix_limit: int,
    source_limit: int,
) -> tuple[bytes, int, int]:
    """Return a verified body prefix, full body size, and schema under hard limits."""
    if type(prefix_limit) is not int or type(source_limit) is not int:
        raise ValueError("blob inspection limits must be integers")
    if prefix_limit < 0 or source_limit < 1:
        raise ValueError("blob inspection limits must be non-negative and positive")
    if parse_oid(oid)[0] != "blob":
        raise KernelError("bounded blob reader requires a blob id")
    handle, stored_size = _open_object(repo, oid)
    try:
        if stored_size > source_limit + _HEADER_LIMIT + 1:
            raise KernelError("repository blob exceeds the inspection source-byte limit")
        header_line = handle.readline(_HEADER_LIMIT + 2)
        if not header_line.endswith(b"\n") or len(header_line) > _HEADER_LIMIT + 1:
            raise KernelError("malformed object envelope")
        raw_header = header_line[:-1]
        try:
            header = json.loads(raw_header)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
            raise KernelError("malformed object envelope") from exc
        if (
            not isinstance(header, dict)
            or set(header) != {"encoding", "schema", "type"}
            or canonical_json(header) != raw_header
            or header.get("encoding") != "raw"
            or header.get("type") != "blob"
        ):
            raise KernelError("non-canonical object header")
        schema = header.get("schema")
        if type(schema) is not int or not 1 <= schema < 2**53:
            raise KernelError("invalid object schema")
        digest = hashlib.sha256(b"blob\0" + str(schema).encode() + b"\0")
        prefix = bytearray()
        total = 0
        while chunk := handle.read(_READ_CHUNK):
            total += len(chunk)
            if total > source_limit:
                raise KernelError("repository blob exceeds the inspection source-byte limit")
            digest.update(chunk)
            remaining = prefix_limit - len(prefix)
            if remaining > 0:
                prefix.extend(chunk[:remaining])
        expected = f"blob:sha256:{digest.hexdigest()}"
        if expected != oid:
            raise KernelError("object id mismatch")
        return bytes(prefix), total, schema
    finally:
        handle.close()
