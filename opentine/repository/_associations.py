"""Reverse association lookup without scanning unrelated repository objects."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from opentine.kernel import KernelError
from opentine.repository._association_index import indexed_targets
from opentine.repository._objects import iter_typed_object_oids

_ASSOCIATION_TYPES = {"annotation", "attestation"}
MAX_ASSOCIATION_SCAN = 100_000


def association_indexes(repo: Any) -> dict[str, dict[str, str]]:
    """Both target indexes, listed once; a caller walking many runs reuses them."""
    indexes = {
        kind: indexed_targets(repo, kind, limit=MAX_ASSOCIATION_SCAN)
        for kind in sorted(_ASSOCIATION_TYPES)
    }
    if any(index is None for index in indexes.values()):
        raise ValueError("typed object scan exceeds its object limit")
    return indexes  # type: ignore[return-value]


def associated_map(
    repo: Any,
    targets: Iterable[str],
    limit: int,
    *,
    indexes: dict[str, dict[str, str]] | None = None,
) -> dict[str, list[str]]:
    selected = set(targets)
    result = {target: [] for target in selected}
    lookup = getattr(repo, "associated_oids", None)
    if callable(lookup):
        for target in selected:
            result[target].extend(lookup(target, limit=limit - sum(map(len, result.values()))))
            if sum(map(len, result.values())) > limit:
                raise KernelError("pack graph exceeds maximum object count")
        return result
    path = getattr(repo, "path", None)
    if path is None:
        raise KernelError("repository cannot enumerate associated objects")
    # The target index narrows the scan to each target's own objects, listed
    # once per call (or once per walk, when the caller passes *indexes*); every
    # candidate is still read and checked.
    if indexes is None:
        indexes = association_indexes(repo)
    count = 0
    for kind, index in indexes.items():
        for digest, named in sorted(index.items()):
            if named not in selected:
                continue
            oid = f"{kind}:sha256:{digest}"
            if repo.get(oid).payload().get("target_id") != named:
                continue
            count += 1
            if count > limit:
                raise KernelError("pack graph exceeds maximum object count")
            result[named].append(oid)
    return result


def evaluations(repo: Any, target: str, get) -> list[dict[str, Any]]:
    """Return bounded evaluation claims that are actually associated with a run."""
    path = getattr(repo, "path", None)
    oids = (
        iter_typed_object_oids(
            path,
            {"attestation"},
            limit=MAX_ASSOCIATION_SCAN,
        )
        if path is not None
        else (
            oid
            for oid in repo.iter_oids(limit=MAX_ASSOCIATION_SCAN)
            if oid.startswith("attestation:")
        )
    )
    found: list[dict[str, Any]] = []
    for oid in oids:
        payload = get(oid).payload()
        if payload.get("target_id") != target:
            continue
        claim = payload.get("claim")
        if not isinstance(claim, dict):
            raise ValueError("attestation claim must be an object")
        if claim.get("kind") == "evaluation":
            found.append({"attestation": oid, "scores": claim.get("scores") or {}})
    return found
