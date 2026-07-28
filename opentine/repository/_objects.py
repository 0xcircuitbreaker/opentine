"""Lazy, bounded enumeration of local content-addressed objects."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from opentine.kernel import OBJECT_TYPES, KernelError, ObjectEnvelope, verify_object
from opentine.repository._paths import atomic_bytes, internal_path

_HEX = frozenset("0123456789abcdef")
MAX_TYPED_OBJECT_SCAN = 100_000


def store_envelope(repo, envelope: ObjectEnvelope) -> str:
    """Persist a caller-validated immutable envelope without rewalking its graph."""
    path = repo._object_path(envelope.oid)
    if not path.exists():
        atomic_bytes(path, envelope.encode())
    else:
        verify_object(path.read_bytes(), envelope.oid, repo._link_exists)
    return envelope.oid


def _entries(directory: Path) -> Iterator[str]:
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                yield entry.name
    except OSError as exc:
        raise KernelError("repository object directory cannot be enumerated") from exc


def _suffixes(directory: Path) -> Iterator[str]:
    yield from _entries(directory)


def _validate_layout(root: Path) -> dict[str, list[str]]:
    objects = internal_path(root, "objects")
    object_types: list[str] = []
    for object_type in _entries(objects):
        if object_type not in OBJECT_TYPES:
            raise KernelError("repository contains an invalid object-type path")
        if not internal_path(root, "objects", object_type).is_dir():
            raise KernelError("repository object-type path is not a directory")
        object_types.append(object_type)
    layout: dict[str, list[str]] = {}
    for object_type in object_types:
        directory = internal_path(root, "objects", object_type)
        prefixes: list[str] = []
        for prefix in _entries(directory):
            if len(prefix) != 2 or any(char not in _HEX for char in prefix):
                raise KernelError("repository contains an invalid object-prefix path")
            if not internal_path(root, "objects", object_type, prefix).is_dir():
                raise KernelError("repository object prefix is not a directory")
            prefixes.append(prefix)
        layout[object_type] = sorted(prefixes)
    return layout


def iter_object_oids(
    root: Path,
    *,
    limit: int | None = None,
    truncate: bool = False,
) -> list[str]:
    if limit is not None and (type(limit) is not int or limit < 1):
        raise ValueError("object listing limit must be a positive integer")
    if truncate and limit is None:
        raise ValueError("truncated object listings require a limit")
    layout = _validate_layout(root)
    found: list[str] = []
    scanned = 0
    for object_type in sorted(layout):
        for prefix in layout[object_type]:
            directory = internal_path(root, "objects", object_type, prefix)
            for suffix in _suffixes(directory):
                scanned += 1
                if limit is not None and scanned > limit:
                    if truncate:
                        return sorted(found)
                    raise ValueError("repository object listing exceeds search limit")
                if len(suffix) != 62 or any(char not in _HEX for char in suffix):
                    if truncate and scanned == limit:
                        return sorted(found)
                    continue
                path = internal_path(root, "objects", object_type, prefix, suffix)
                if not path.is_file():
                    raise KernelError("repository object path is not a regular file")
                found.append(f"{object_type}:sha256:{prefix}{suffix}")
                if truncate and scanned == limit:
                    return sorted(found)
    return sorted(found)


def iter_typed_object_oids(
    root: Path,
    object_types: set[str],
    *,
    limit: int = MAX_TYPED_OBJECT_SCAN,
) -> Iterator[str]:
    """Stream selected object types under a hard directory-entry scan limit."""
    if type(limit) is not int or limit < 1:
        raise ValueError("typed object scan limit must be a positive integer")
    layout = _validate_layout(root)
    scanned = 0
    for object_type in sorted(object_types):
        for prefix in layout.get(object_type, []):
            directory = internal_path(root, "objects", object_type, prefix)
            for suffix in _suffixes(directory):
                scanned += 1
                if scanned > limit:
                    raise ValueError("typed object scan exceeds its object limit")
                if len(suffix) != 62 or any(char not in _HEX for char in suffix):
                    continue
                path = internal_path(root, "objects", object_type, prefix, suffix)
                if not path.is_file():
                    raise KernelError("repository object path is not a regular file")
                yield f"{object_type}:sha256:{prefix}{suffix}"
