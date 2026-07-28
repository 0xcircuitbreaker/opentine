"""Reverse association lookup without scanning unrelated repository objects."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from opentine.kernel import KernelError
from opentine.repository._objects import iter_typed_object_oids

_ASSOCIATION_TYPES = {"annotation", "attestation"}
MAX_ASSOCIATION_SCAN = 100_000


def associated_map(repo: Any, targets: Iterable[str], limit: int) -> dict[str, list[str]]:
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
    count = 0
    for oid in iter_typed_object_oids(
        path,
        _ASSOCIATION_TYPES,
        limit=MAX_ASSOCIATION_SCAN,
    ):
        target = repo.get(oid).payload().get("target_id")
        if target not in selected:
            continue
        count += 1
        if count > limit:
            raise KernelError("pack graph exceeds maximum object count")
        result[target].append(oid)
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
