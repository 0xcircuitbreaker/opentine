"""Which object each annotation and attestation names: a cache for reverse lookups.

Annotations and attestations name their subject by ``target_id``; nothing links
*to* them, so finding a run's associations meant decoding every one in the
repository. The unheaded-annotation fallback did so on each ``load_run`` and
``put_run`` of a run without an annotation ref -- minutes at 100,000
annotations, and a hard failure past them, which a remote could reach by
serving annotations over a few fetches -- and so did every pack walk, the
put-run preflight, and pruning the unadopted record.

This index maps each such object to its target, one file per type under
``.tine/indexes/``. It is a cache, never an authority: the object directory is
listed on every use (no object is read), any listed object the index lacks is
decoded and added, entries for objects that are gone are dropped, and a damaged
index is rebuilt. Callers still read each candidate's payload, so the index only
narrows which objects get decoded.
"""

from __future__ import annotations

import os
import re
from typing import Any

from opentine.kernel import KernelError
from opentine.repository._objects import MAX_TYPED_OBJECT_SCAN, iter_typed_object_oids
from opentine.repository._paths import atomic_bytes, internal_path

#: Objects of one type listed beyond the typed-scan bound make the index give up
#: (``None``) rather than read an unbounded directory; callers degrade.
_MAX_INDEXED = MAX_TYPED_OBJECT_SCAN
_TARGET = re.compile(r"[a-z]{1,16}:sha256:[0-9a-f]{64}")
_LINE = re.compile(rf"([0-9a-f]{{64}}) ({_TARGET.pattern}|-)")
_LINE_BYTES = 64 + 1 + 16 + 8 + 64 + 1
_TYPES = frozenset({"annotation", "attestation"})


def _path(root, object_type: str) -> Any:
    return internal_path(root, "indexes", f"{object_type}-targets")


def _read(root, object_type: str) -> dict[str, str]:
    """The stored index, or an empty one when it is missing or damaged."""
    try:
        fd = os.open(_path(root, object_type), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return {}
    try:
        with os.fdopen(fd, "rb") as handle:
            data = handle.read(_MAX_INDEXED * _LINE_BYTES + 1)
        if len(data) > _MAX_INDEXED * _LINE_BYTES:
            return {}
        index: dict[str, str] = {}
        for line in data.decode("ascii").splitlines():
            match = _LINE.fullmatch(line)
            if match is None:
                return {}
            index[match.group(1)] = match.group(2)
        return index
    except (OSError, UnicodeDecodeError, ValueError):
        return {}


def _write(root, object_type: str, index: dict[str, str]) -> None:
    body = "".join(f"{oid} {target}\n" for oid, target in sorted(index.items()))
    try:
        atomic_bytes(_path(root, object_type), body.encode("ascii"))
    except (OSError, KernelError, ValueError):
        pass  # a cache: the next use lists and decodes again


def _target(repo: Any, oid: str) -> str | None:
    """The object id *oid* names, ``-`` for anything else, None when unreadable."""
    try:
        target = repo.get(oid).payload().get("target_id")
    except (KeyError, ValueError, KernelError, AttributeError):
        return None
    if isinstance(target, str) and _TARGET.fullmatch(target):
        return target
    return "-"


def indexed_targets(
    repo: Any, object_type: str = "annotation", *, limit: int | None = None
) -> dict[str, str] | None:
    """Object digest -> target id for every *object_type* object present.

    ``None`` when the repository holds more of them than the index covers. An
    object that cannot be read is left out (and retried on the next use).
    """
    if object_type not in _TYPES:
        raise ValueError("only annotations and attestations are indexed")
    root = repo.path
    prefix = f"{object_type}:sha256:"
    try:
        bound = _MAX_INDEXED if limit is None else limit
        listed = list(iter_typed_object_oids(root, {object_type}, limit=bound))
    except ValueError:
        return None
    stored = _read(root, object_type)
    current: dict[str, str] = {}
    for oid in listed:
        digest = oid[len(prefix) :]
        target = stored.get(digest)
        if target is None:
            target = _target(repo, oid)
            if target is None:
                continue
        current[digest] = target
    if current != stored:
        _write(root, object_type, current)
    return current


def associated(repo: Any, target: str, object_types=_TYPES) -> list[str] | None:
    """The ids of *object_types* objects naming *target*; None past the index bound."""
    found: list[str] = []
    for object_type in sorted(object_types):
        index = indexed_targets(repo, object_type)
        if index is None:
            return None
        found.extend(
            f"{object_type}:sha256:{oid}" for oid, named in index.items() if named == target
        )
    return sorted(found)


def still_needed(repo, oids: set[str]) -> set[str]:
    """Unadopted entries the fallback could still read: present, for a run with no head.

    Entries for annotations that are gone, or for runs that now have an
    annotation ref (the fallback never reads those), are safe to forget.
    """
    from opentine.repository._annotations import annotation_ref

    targets = indexed_targets(repo)
    if targets is None:
        return set(oids)  # too many annotations to look up: keep everything
    headed: dict[str, bool] = {}
    kept = set()
    for oid in oids:
        target = targets.get(oid.removeprefix("annotation:sha256:"))
        if target is None and not repo.has(oid):
            continue
        if target and target.startswith("run:"):
            if target not in headed:
                headed[target] = bool(repo.read_ref(annotation_ref(target)))
            if headed[target]:
                continue
        kept.add(oid)
    return kept
