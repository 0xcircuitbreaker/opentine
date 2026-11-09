"""A remote's Reviews: ``<objects root>/.reviews/<tenant>/<review_id>/`` (0.47, ``caps.reviews``).

Beside ``.projects`` and ``.tombstones``, outside every tenant's object tree and
ref listing. ``v/<seq>.json`` holds each ``opentine.review`` version and
``d/<n>.json`` each gate decision, in arrival order, exactly as their
reviewers signed them: the server never signs one. Every file is created with
``O_EXCL``, so two writers racing for the same next version cannot both win
(the compare-and-swap behind ``PUT reviews/<id>``).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from opentine._review_rules import ID
from opentine.kernel import canonical_json
from opentine.remote.backend import valid_tenant

MAX_BYTES = 1 << 20
MAX_ITEMS = 10_000


def _dir(root: Path, tenant: str, review_id: str | None = None) -> Path:
    base = Path(root) / ".reviews" / valid_tenant(tenant)
    if review_id is None:
        return base
    if not ID.fullmatch(review_id):
        raise ValueError("a review id is [a-z0-9][a-z0-9._-]{0,63}")
    return base / review_id


def _items(folder: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    while len(out) < MAX_ITEMS:
        try:
            raw = (folder / f"{len(out):08d}.json").read_bytes()
        except FileNotFoundError:
            break
        if len(raw) > MAX_BYTES:
            raise ValueError("a stored review record exceeds its size limit")
        out.append(json.loads(raw))
    return out


def versions(root: Path, tenant: str, review_id: str) -> list[dict[str, Any]]:
    return _items(_dir(root, tenant, review_id) / "v")


def decisions(root: Path, tenant: str, review_id: str) -> list[dict[str, Any]]:
    return _items(_dir(root, tenant, review_id) / "d")


def names(root: Path, tenant: str) -> list[str]:
    base = _dir(root, tenant)
    if not base.is_dir():
        return []
    return sorted(p.name for p in base.iterdir() if ID.fullmatch(p.name) and (p / "v").is_dir())


def _create(path: Path, record: dict[str, Any]) -> bool:
    data = canonical_json(record)
    if len(data) > MAX_BYTES:
        raise ValueError("review record exceeds its size limit")
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


def append(root: Path, tenant: str, record: dict[str, Any]) -> bool:
    """Store *record* as version ``record["seq"]``; ``False`` when that version exists."""
    folder = _dir(root, tenant, str(record["review_id"])) / "v"
    return _create(folder / f"{int(record['seq']):08d}.json", record)


def decide(root: Path, tenant: str, record: dict[str, Any]) -> None:
    """Store a decision as the next one in arrival order."""
    folder = _dir(root, tenant, str(record["review_id"])) / "d"
    for _ in range(64):
        if _create(folder / f"{len(_items(folder)):08d}.json", record):
            return
    raise ValueError("the review's decisions are too contended: retry")


__all__ = ["append", "decide", "decisions", "names", "versions"]
