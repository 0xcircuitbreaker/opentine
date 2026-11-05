"""Detached ``tine-sig/3`` blocks of runs installed from v4 files (SPEC 9.10).

A ``tine-sig/3`` block signs a run's root and annotation head; it is not an
object, so it cannot live in the object store without changing what it signs,
and an attestation (``tine-attest/*``) is a different message. Each run's blocks
are kept in ``signatures/v4/<root hex>.json`` beside the store:

    {"entries": [{"annotations_head": <oid|null>, "block": {...}}, ...],
     "kind": "tine-sig-sidecar/1", "root": <run oid>}

canonical JSON, at most 256 entries. The file names the root oid, so ``tine gc``
treats it as a root like any other file it scans. Packs carry objects only;
``tine bundle`` (and ``bundle push/fetch``) carries the blocks in its manifest
(``_bundle_sigs``).
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from opentine.kernel import canonical_json, parse_oid
from opentine.repository import _winretry
from opentine.repository._lockfile import acquire
from opentine.repository._paths import atomic_bytes, internal_path

SIDECAR_KIND = "tine-sig-sidecar/1"
MAX_SIDECAR_ENTRIES = 256
MAX_SIDECAR_BYTES = 4 * 1024 * 1024


def sidecar_path(repo: Any, root: str) -> Path:
    return internal_path(repo.path, "signatures", "v4", f"{parse_oid(root)[1]}.json")


def _entries(repo: Any, root: str) -> list[dict[str, Any]]:
    path = sidecar_path(repo, root)
    if not path.is_file():
        return []
    raw = path.read_bytes()
    if len(raw) > MAX_SIDECAR_BYTES:
        raise ValueError(f"signature sidecar {path.name} exceeds {MAX_SIDECAR_BYTES} bytes")
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"signature sidecar {path.name} is malformed") from exc
    entries = value.get("entries") if isinstance(value, dict) else None
    if (
        value.get("kind") != SIDECAR_KIND
        or value.get("root") != root
        or not isinstance(entries, list)
        or not all(isinstance(e, dict) and isinstance(e.get("block"), dict) for e in entries)
    ):
        raise ValueError(f"signature sidecar {path.name} is malformed")
    return entries


def entries_for(repo: Any, root: str) -> list[dict[str, Any]]:
    """Every stored ``{annotations_head, block}`` entry for *root*."""
    return _entries(repo, root)


def signatures_for(repo: Any, root: str, head: str | None) -> list[dict[str, Any]]:
    """The stored blocks that signed *root* with annotation head *head*."""
    return [e["block"] for e in _entries(repo, root) if e.get("annotations_head") == head]


_LOCK_WAIT_SECONDS = 10.0


@contextlib.contextmanager
def _sidecar_lock(path: Path) -> Iterator[None]:
    """Serialize read-modify-write of one sidecar so concurrent signers keep every block."""
    lock = path.with_name(path.name + ".lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    while True:
        try:
            fd = acquire(lock)
            break
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise ValueError(
                    f"signature sidecar {path.name} is locked by a concurrent writer"
                ) from None
            time.sleep(0.01)
    os.close(fd)
    try:
        yield
    finally:
        with contextlib.suppress(FileNotFoundError):
            _winretry.unlink(lock)


def add_signatures(repo: Any, root: str, head: str | None, blocks: list[Any]) -> int:
    """Merge *blocks* (already shape-checked by the v4 reader); returns how many are new."""
    with _sidecar_lock(sidecar_path(repo, root)):
        return _add_signatures_locked(repo, root, head, blocks)


def _add_signatures_locked(repo: Any, root: str, head: str | None, blocks: list[Any]) -> int:
    entries = _entries(repo, root)
    known = {canonical_json(entry) for entry in entries}
    added = 0
    for block in blocks:
        entry = {"annotations_head": head, "block": block}
        if canonical_json(entry) not in known:
            known.add(canonical_json(entry))
            entries.append(entry)
            added += 1
    if not added:
        return 0
    if len(entries) > MAX_SIDECAR_ENTRIES:
        raise ValueError(f"run would hold more than {MAX_SIDECAR_ENTRIES} detached signatures")
    document = {"entries": entries, "kind": SIDECAR_KIND, "root": root}
    data = canonical_json(document) + b"\n"
    if len(data) > MAX_SIDECAR_BYTES:
        # Refuse here: a sidecar past the cap would make every later read fail.
        raise ValueError(f"signature sidecar would exceed {MAX_SIDECAR_BYTES} bytes")
    atomic_bytes(sidecar_path(repo, root), data)
    return added


__all__ = ["SIDECAR_KIND", "add_signatures", "sidecar_path", "signatures_for"]
