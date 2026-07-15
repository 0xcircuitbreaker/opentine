"""Deep repository integrity and event-DAG verification."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from opentine.kernel import KernelError, parse_oid, verify_object

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
            parents[oid] = [
                *(payload.get("parent_ids") or []),
                *(payload.get("causal_ids") or []),
            ]
    children: dict[str, list[str]] = defaultdict(list)
    degrees = {oid: 0 for oid in parents}
    for child, values in parents.items():
        for parent in values:
            if parent in parents:
                children[parent].append(child)
                degrees[child] += 1
    ready = deque(oid for oid, degree in degrees.items() if degree == 0)
    while ready:
        for child in children[ready.popleft()]:
            degrees[child] -= 1
            if degrees[child] == 0:
                ready.append(child)
    cycles = sorted(oid for oid, degree in degrees.items() if degree)
    return [f"event graph cycle reachable from {oid}" for oid in cycles]


def fsck(repo: Repo, *, deep: bool = True) -> FsckResult:
    errors: list[str] = []
    oids = repo.iter_oids()
    try:
        for oid in repo.shallow_oids():
            parse_oid(oid)
    except (KernelError, OSError, UnicodeError) as exc:
        errors.append(f"shallow: {exc}")
    for oid in oids:
        try:
            verify_object(repo.raw(oid), oid, repo._link_exists if deep else None)
        except (KernelError, OSError) as exc:
            errors.append(f"{oid}: {exc}")
    try:
        refs = repo.list_refs()
    except (KernelError, OSError, UnicodeError, ValueError) as exc:
        errors.append(f"refs: {exc}")
        refs = {}
    for name, oid in refs.items():
        try:
            repo._ref_name(name)
            parse_oid(oid)
        except (KernelError, ValueError) as exc:
            errors.append(f"ref {name}: {exc}")
            continue
        if not repo.has(oid):
            errors.append(f"ref {name}: missing {oid}")
    if deep:
        errors.extend(_cycle_errors(repo, oids))
    return FsckResult(not errors, len(oids), len(refs), tuple(errors))
