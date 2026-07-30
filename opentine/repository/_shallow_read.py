"""Shallow-fetch boundary decisions for the graph read surface."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from opentine.kernel import KernelError


class ShallowBoundary:
    """Distinguish objects a depth-limited fetch deliberately cut away.

    The pack writer records every cut link in the repository's shallow state,
    so readers can tell "absent by design" (stop there, as git log does on a
    shallow clone) from "absent and broken" (still an error).
    """

    def __init__(self, repo: Any):
        self._repo = repo
        reader = getattr(repo, "_shallow_set", None)
        self._cut = reader() if callable(reader) else frozenset()

    def cuts(self, oid: str) -> bool:
        return oid in self._cut and not self._repo.has(oid)

    def present(self, oids: Iterable[str]) -> list[str]:
        return [oid for oid in oids if not self.cuts(oid)]


def shallow_cut_error(operation: str, oid: str) -> KernelError:
    """The one typed refusal every boundary-crossing materialization raises."""
    return KernelError(
        f"{operation} requires {oid}, which is beyond this repository's "
        "shallow fetch boundary; deepen the fetch (fetch/clone with a "
        "higher or no --depth) to retrieve it"
    )


def require_deep(repo: Any, oids: Iterable[str], operation: str) -> None:
    """Refuse a full materialization that a shallow fetch cannot satisfy."""
    boundary = ShallowBoundary(repo)
    for oid in oids:
        if boundary.cuts(oid):
            raise shallow_cut_error(operation, oid)
