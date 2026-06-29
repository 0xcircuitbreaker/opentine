"""Ordered, pure-function ``.tine`` format migrations.

Each migration is a ``dict -> dict`` function registered by ``(from, to)``
adjacent version pair. ``migrate_dict`` chains them to bring an artifact up to a
target version. This module imports only from ``_canon``/``_version`` (never from
``graph``), so ``graph.load`` can call ``migrate_dict`` without an import cycle.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

from opentine._canon import FORMAT_VERSION, SUPPORTED_VERSIONS, _integrity_digest
from opentine._version import __version__ as _TOOL_VERSION

Migration = Callable[[dict[str, Any]], dict[str, Any]]

MIGRATIONS: dict[tuple[int, int], Migration] = {}


class MigrationError(ValueError):
    """Raised when an artifact cannot be migrated to the requested version."""


def register(from_version: int, to_version: int) -> Callable[[Migration], Migration]:
    """Register a migration for an adjacent ``(from, to)`` version pair."""

    def decorator(func: Migration) -> Migration:
        if to_version != from_version + 1:
            raise ValueError("migrations must be registered for adjacent versions")
        MIGRATIONS[(from_version, to_version)] = func
        return func

    return decorator


def detect_version(data: dict[str, Any]) -> int:
    version = data.get("format_version")
    if version is None:
        raise MigrationError("missing format_version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise MigrationError(f"non-integer format_version {version!r}")
    return version


def migrate_dict(data: dict[str, Any], target: int = FORMAT_VERSION) -> dict[str, Any]:
    """Return a *new* dict migrated to ``target`` (the input is never mutated).

    Rejects missing/non-integer versions, downgrades, and any gap with no
    registered migration. A file already at ``target`` is returned as a deep copy
    unchanged.
    """
    if not isinstance(data, dict):
        raise MigrationError("artifact root is not an object")
    current = detect_version(data)
    if current == target:
        return copy.deepcopy(data)
    if current > target:
        raise MigrationError(f"cannot downgrade format_version {current} -> {target}")
    if current not in SUPPORTED_VERSIONS and current >= max(SUPPORTED_VERSIONS):
        raise MigrationError(
            f"format_version {current} is newer than this build supports "
            f"(max {max(SUPPORTED_VERSIONS)})"
        )

    out = copy.deepcopy(data)
    for step_from in range(current, target):
        migration = MIGRATIONS.get((step_from, step_from + 1))
        if migration is None:
            raise MigrationError(f"no migration registered for v{step_from} -> v{step_from + 1}")
        out = migration(out)
    return out


@register(1, 2)
def _v1_to_v2(data: dict[str, Any]) -> dict[str, Any]:
    """v1 -> v2: additive only.

    Sets ``format_version=2``, records a migration breadcrumb, drops any stray
    signature (the in-digest ``format_version`` change invalidates it), and
    recomputes the body digest. No tags/budget/usage fields are added — those
    appear only when a feature writes them.
    """
    data["format_version"] = 2
    metadata = data.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
        data["metadata"] = metadata

    chain = metadata.setdefault("migration", [])
    if isinstance(chain, list):
        chain.append({"from": 1, "to": 2, "tool": f"opentine/{_TOOL_VERSION}"})

    integrity = metadata.get("integrity")
    if isinstance(integrity, dict):
        integrity.pop("signature", None)
        integrity["algorithm"] = "sha256"
        integrity["digest"] = _integrity_digest(data)

    return data
