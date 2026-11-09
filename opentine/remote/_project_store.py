"""A remote's project manifests: ``<objects root>/.projects/<tenant>/<seq>.json`` (0.46.1).

Beside ``.tombstones`` and ``.holds``, outside every tenant's object tree, so a
manifest is neither an object a pack carries nor a ref ``GET refs`` lists
(pre-0.46.1 clients fetch, clone and push exactly as before). One canonical-JSON
``opentine.project`` per version, stored exactly as its owner signed it; the
server never signs one. Version *n* is created with ``O_EXCL``, so two writers
racing for the same next version cannot both win: that is the compare-and-swap
behind ``PUT project``. ``social.json`` (optional) holds the count-only stars
and watches ``caps.social_export`` reports.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from opentine._signed_record import is_count
from opentine.kernel import canonical_json
from opentine.remote.backend import valid_tenant

MAX_BYTES = 64 * 1024
MAX_VERSIONS = 10_000


def _dir(root: Path, tenant: str) -> Path:
    return Path(root) / ".projects" / valid_tenant(tenant)


def _path(root: Path, tenant: str, seq: int) -> Path:
    return _dir(root, tenant) / f"{seq:08d}.json"


def count(root: Path, tenant: str) -> int:
    """How many versions are stored (they are 0..count-1, without gaps)."""
    seq = 0
    while seq < MAX_VERSIONS and _path(root, tenant, seq).is_file():
        seq += 1
    return seq


def read(root: Path, tenant: str, seq: int) -> dict[str, Any] | None:
    try:
        raw = _path(root, tenant, seq).read_bytes()
    except (FileNotFoundError, ValueError):
        return None
    if len(raw) > MAX_BYTES:
        raise ValueError("stored project manifest exceeds its size limit")
    return json.loads(raw)


def head(root: Path, tenant: str) -> dict[str, Any] | None:
    total = count(root, tenant)
    return read(root, tenant, total - 1) if total else None


def page(root: Path, tenant: str, start: int, size: int) -> tuple[list[dict[str, Any]], int]:
    """Versions ``start..start+size-1`` that exist, and the total stored."""
    total = count(root, tenant)
    versions = [read(root, tenant, seq) for seq in range(start, min(total, start + size))]
    return [v for v in versions if v is not None], total


def append(root: Path, tenant: str, record: dict[str, Any]) -> bool:
    """Store *record* as version ``record["seq"]``; ``False`` when that version exists."""
    data = canonical_json(record)
    if len(data) > MAX_BYTES:
        raise ValueError("project manifest exceeds its size limit")
    path = _path(root, tenant, int(record["seq"]))
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
    except FileExistsError:
        return False
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return True


def social(root: Path, tenant: str) -> dict[str, int]:
    """``{"stars": n, "watches": n}``: counts only, never who."""
    try:
        value = json.loads((_dir(root, tenant) / "social.json").read_bytes())
    except (FileNotFoundError, ValueError):
        value = {}
    value = value if isinstance(value, dict) else {}
    return {name: value[name] if is_count(value.get(name)) else 0 for name in ("stars", "watches")}


__all__ = ["MAX_VERSIONS", "append", "count", "head", "page", "read", "social"]
