"""Reverse association lookup without scanning unrelated repository objects."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from opentine.kernel import KernelError
from opentine.repository._objects import iter_typed_object_oids

_ASSOCIATION_TYPES = {"annotation", "attestation"}


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
    for oid in iter_typed_object_oids(path, _ASSOCIATION_TYPES):
        target = repo.get(oid).payload().get("target_id")
        if target not in selected:
            continue
        count += 1
        if count > limit:
            raise KernelError("pack graph exceeds maximum object count")
        result[target].append(oid)
    return result
