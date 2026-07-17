"""Bounded enumeration for the reference filesystem object store."""

from __future__ import annotations

from pathlib import Path

MAX_OBJECT_LIST = 100_000


def list_objects(
    root: Path,
    *,
    limit: int | None = None,
    truncate: bool = False,
) -> list[str]:
    if limit is not None and (type(limit) is not int or limit < 1):
        raise ValueError("object listing limit must be a positive integer")
    if truncate and limit is None:
        raise ValueError("truncated object listings require a limit")
    cap = min(limit or MAX_OBJECT_LIST, MAX_OBJECT_LIST)
    found: list[str] = []
    if not root.exists():
        return found
    for object_type in root.iterdir():
        if not object_type.is_dir():
            continue
        for prefix in object_type.iterdir():
            for item in prefix.iterdir() if prefix.is_dir() else []:
                digest = prefix.name + item.name
                if len(digest) != 64:
                    continue
                found.append(f"{object_type.name}:sha256:{digest}")
                if truncate and len(found) == cap:
                    return sorted(found)
                if len(found) > cap:
                    raise ValueError("tenant object listing exceeds reference backend limit")
    return sorted(found)
