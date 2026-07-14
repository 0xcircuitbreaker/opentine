"""Deep repository integrity and event-DAG verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from opentine.kernel import KernelError, verify_object

if TYPE_CHECKING:
    from opentine.repository.store import Repo


@dataclass(frozen=True)
class FsckResult:
    ok: bool
    objects: int
    refs: int
    errors: tuple[str, ...]


def _cycle_errors(repo: Repo, oids: list[str]) -> list[str]:
    parents: dict[str, list[str]] = {}
    for oid in oids:
        if oid.startswith("event:"):
            try:
                payload = repo.get(oid).payload()
            except (KernelError, OSError):
                continue
            parents[oid] = list(payload.get("parent_ids") or [])
    visiting: set[str] = set()
    visited: set[str] = set()
    cycles: set[str] = set()

    def visit(oid: str) -> bool:
        if oid in visiting:
            cycles.add(oid)
            return True
        if oid in visited:
            return False
        visiting.add(oid)
        cyclic = any(parent in parents and visit(parent) for parent in parents[oid])
        visiting.remove(oid)
        visited.add(oid)
        if cyclic:
            cycles.add(oid)
        return cyclic

    for oid in parents:
        visit(oid)
    return [f"event graph cycle reachable from {oid}" for oid in sorted(cycles)]


def fsck(repo: Repo, *, deep: bool = True) -> FsckResult:
    errors: list[str] = []
    oids = repo.iter_oids()
    for oid in oids:
        try:
            verify_object(repo.raw(oid), oid, repo._link_exists if deep else None)
        except (KernelError, OSError) as exc:
            errors.append(f"{oid}: {exc}")
    refs = repo.list_refs()
    for name, oid in refs.items():
        if not repo.has(oid):
            errors.append(f"ref {name}: missing {oid}")
    if deep:
        errors.extend(_cycle_errors(repo, oids))
    return FsckResult(not errors, len(oids), len(refs), tuple(errors))
