"""Ordered, pure-function ``.tine`` format migrations.

Each migration is a ``dict -> dict`` function registered by ``(from, to)``
adjacent version pair. ``migrate_dict`` chains them to bring an artifact up to a
target version. This module imports only from ``_canon``/``_version`` (never from
``graph``), so ``graph.load`` can call ``migrate_dict`` without an import cycle.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable
from typing import Any

from opentine._canon import FORMAT_VERSION, SUPPORTED_VERSIONS, _canonical_bytes, _integrity_digest
from opentine._version import __version__ as _TOOL_VERSION

Migration = Callable[[dict[str, Any]], dict[str, Any]]

MIGRATIONS: dict[tuple[int, int], Migration] = {}

#: The pre-versioned 0.1.0 "linear" format (no format_version, flat ``steps``
#: list, ``type == "Run"``) is treated as version 0 for migration purposes.
LEGACY_VERSION = 0


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


def is_legacy_linear(data: dict[str, Any]) -> bool:
    """True for the 0.1.0 pre-versioned linear format.

    Keyed on the ``type == "Run"`` marker that 0.1.0 always wrote, so a generic
    ``{"steps": [...]}`` blob is NOT misclassified as importable.
    """
    return (
        isinstance(data, dict)
        and data.get("type") == "Run"
        and isinstance(data.get("steps"), list)
        and "graph" not in data
    )


def detect_version(data: dict[str, Any]) -> int:
    version = data.get("format_version")
    if version is None:
        if is_legacy_linear(data):
            return LEGACY_VERSION
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

    chain = metadata.get("migration")
    if not isinstance(chain, list):  # repair a missing/corrupt breadcrumb field
        chain = []
        metadata["migration"] = chain
    chain.append({"from": 1, "to": 2, "tool": f"opentine/{_TOOL_VERSION}"})

    integrity = metadata.get("integrity")
    if not isinstance(integrity, dict):
        integrity = {}
        metadata["integrity"] = integrity
    integrity.pop("signature", None)
    integrity["algorithm"] = "sha256"
    integrity["digest"] = _integrity_digest(data)

    return data


def _legacy_step_id(
    kind: str, parent_ids: list[str], inputs: dict, outputs: dict, model_info: str
) -> str:
    """Recompute a full content-addressed step id (mirrors graph.step_id).

    Kept in sync with ``graph.step_id`` deliberately — replicated here rather than
    imported to avoid a migrations->graph import cycle.
    """
    payload = {
        "kind": kind,
        "parent_ids": list(parent_ids),
        "inputs": inputs or {},
        "outputs": outputs or {},
        "model_info": model_info,
        "tool_info": {},
        "error": {},
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


@register(LEGACY_VERSION, 1)
def _v0_to_v1(data: dict[str, Any]) -> dict[str, Any]:
    """Best-effort import of the 0.1.0 linear format into the v1 graph format.

    0.1.0 had no format_version, a flat ``steps`` list, short 12-char step ids,
    and a singular ``parent_id``. Step ids are RECOMPUTED as full content hashes
    (so they change), parent links are remapped, and tool_info/error (absent in
    0.1.0) default to empty. The legacy integrity digest is dropped; _v1_to_v2
    finalizes a fresh one.
    """
    id_map: dict[str, str] = {}
    steps: dict[str, Any] = {}
    order: list[str] = []
    for legacy in data.get("steps") or []:
        if not isinstance(legacy, dict):
            continue
        kind = legacy.get("kind", "think")
        inputs = legacy.get("inputs") or {}
        outputs = legacy.get("outputs") or {}
        model_info = legacy.get("model_info", "")
        old_parent = legacy.get("parent_id")
        parent_ids = [id_map[old_parent]] if old_parent in id_map else []
        new_id = _legacy_step_id(kind, parent_ids, inputs, outputs, model_info)
        if legacy.get("id") is not None:
            id_map[legacy["id"]] = new_id
        steps[new_id] = {
            "id": new_id,
            "parent_ids": parent_ids,
            "kind": kind,
            "inputs": inputs,
            "outputs": outputs,
            "model_info": model_info,
            "tool_info": {},
            "error": {},
            "timestamp": float(legacy.get("timestamp") or 0.0),
            "duration": float(legacy.get("duration") or 0.0),
            "cost": float(legacy.get("cost") or 0.0),
        }
        if new_id not in order:
            order.append(new_id)

    metadata = dict(data.get("metadata") or {})
    metadata.setdefault("model_info", data.get("model_info", ""))
    metadata.setdefault("system_prompt", data.get("system_prompt", ""))
    metadata.setdefault("user_prompt", data.get("user_prompt", ""))
    metadata.pop("integrity", None)  # legacy digest is meaningless under v1/v2 rules
    chain = metadata.get("migration")
    if not isinstance(chain, list):
        chain = []
    metadata["migration"] = [
        *chain,
        {"from": 0, "to": 1, "tool": f"opentine/{_TOOL_VERSION}", "note": "0.1.0-linear-import"},
    ]

    return {
        "format_version": 1,
        "run_id": data.get("id") or data.get("run_id"),
        "created_at": data.get("created_at", 0.0),
        "status": data.get("status", "completed"),
        "graph": {"steps": steps, "order": order},
        "refs": {"main": order[-1] if order else ""},
        "transcript": data.get("transcript", []),
        "manifest": data.get("manifest", {}),
        "policies": data.get("policies", {}),
        "cache": data.get("cache", {}),
        "metadata": metadata,
    }
