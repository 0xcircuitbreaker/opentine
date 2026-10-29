"""Lazy, bounded enumeration of local content-addressed objects."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from opentine.kernel import OBJECT_TYPES, KernelError, ObjectEnvelope
from opentine.repository import _dir_cache
from opentine.repository._packs import pack_set
from opentine.repository._paths import internal_path

_HEX = frozenset("0123456789abcdef")
MAX_TYPED_OBJECT_SCAN = 100_000


def store_envelope(repo, envelope: ObjectEnvelope) -> str:
    """Persist a caller-validated immutable envelope without rewalking its graph."""
    from opentine.repository._storage import write_object

    write_object(repo, envelope.oid, envelope.encode())
    # An estimate of new loose objects for the auto-pack hook (_autopack.after_write).
    repo.__dict__["_autopack_writes"] = repo.__dict__.get("_autopack_writes", 0) + 1
    repo.__dict__.setdefault("_autopack_own", set()).add(envelope.oid)  # see after_write
    return envelope.oid


def _entries(directory: Path) -> Iterator[str]:
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                yield entry.name
    except OSError as exc:
        raise KernelError("repository object directory cannot be enumerated") from exc


def _suffixes(directory: Path) -> Iterator[str]:
    # readdir order is a per-filesystem hash order; identical repositories must
    # enumerate — and therefore diff and pack — identically everywhere.
    yield from sorted(_entries(directory))


def _validate_layout(root: Path) -> dict[str, list[str]]:
    objects = internal_path(root, "objects")
    object_types = _dir_cache.cached(objects, lambda: _scan_types(root, objects))
    layout: dict[str, list[str]] = {}
    for object_type in object_types:
        directory = objects / object_type
        prefixes = _dir_cache.cached(directory, lambda: _scan_prefixes(root, object_type))
        layout[object_type] = list(prefixes)
    return layout


def _children(directory: Path) -> Iterator[os.DirEntry]:
    try:
        with os.scandir(directory) as entries:
            yield from entries
    except OSError as exc:
        raise KernelError("repository object directory cannot be enumerated") from exc


def _real_dir(entry: os.DirEntry) -> bool:
    """What internal_path accepts as a child directory of a validated directory."""
    junction = getattr(entry, "is_junction", None)
    if entry.is_symlink() or (callable(junction) and junction()):
        raise KernelError("repository path contains a symlink")
    return entry.is_dir(follow_symlinks=False)


def _scan_types(root: Path, objects: Path) -> tuple[str, ...]:
    object_types: list[str] = []
    for entry in _children(objects):
        if entry.name not in OBJECT_TYPES:
            # A name that is not an object type holds no objects: one stray
            # .DS_Store must not take down fsck, search, and pack (refs/ policy).
            continue
        if not _real_dir(entry):
            raise KernelError("repository object-type path is not a directory")
        object_types.append(entry.name)
    return tuple(object_types)


def _scan_prefixes(root: Path, object_type: str) -> tuple[str, ...]:
    directory = internal_path(root, "objects", object_type)
    prefixes: list[str] = []
    for entry in _children(directory):
        prefix = entry.name
        if len(prefix) != 2 or any(char not in _HEX for char in prefix):
            continue  # not a legal object prefix, so not part of the store
        if not _real_dir(entry):
            raise KernelError("repository object prefix is not a directory")
        prefixes.append(prefix)
    return tuple(sorted(prefixes))


def _typed_suffixes(root: Path, object_type: str, prefix: str) -> tuple[str, ...]:
    """Validated object-file suffixes in one fan-out directory (see _dir_cache)."""

    def scan() -> tuple[str, ...]:
        directory = internal_path(root, "objects", object_type, prefix)
        found: list[str] = []
        for entry in _children(directory):
            suffix = entry.name
            if len(suffix) == 62 and all(char in _HEX for char in suffix):
                if entry.is_symlink():
                    raise KernelError("repository path contains a symlink")
                if not entry.is_file(follow_symlinks=False):
                    raise KernelError("repository object path is not a regular file")
                if entry.stat(follow_symlinks=False).st_nlink > 1:
                    raise KernelError("repository path contains a hard-linked file")
            found.append(suffix)
        return tuple(sorted(found))

    return _dir_cache.cached(Path(root) / "objects" / object_type / prefix, scan)


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
    loose = set(found)
    for oid in pack_set(root).oids():
        if oid in loose:
            continue
        scanned += 1
        if limit is not None and scanned > limit:
            if truncate:
                return sorted(found)
            raise ValueError("repository object listing exceeds search limit")
        found.append(oid)
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
            for suffix in _typed_suffixes(root, object_type, prefix):
                scanned += 1
                if scanned > limit:
                    raise ValueError("typed object scan exceeds its object limit")
                if len(suffix) != 62 or any(char not in _HEX for char in suffix):
                    continue
                yield f"{object_type}:sha256:{prefix}{suffix}"
    for oid in pack_set(root).oids(object_types):
        if internal_path(root, "objects", *_loose_parts(oid)).is_file():
            continue  # already yielded loose
        scanned += 1
        if scanned > limit:
            raise ValueError("typed object scan exceeds its object limit")
        yield oid


def _loose_parts(oid: str) -> tuple[str, str, str]:
    object_type, _, digest = oid.split(":", 2)
    return object_type, digest[:2], digest[2:]
