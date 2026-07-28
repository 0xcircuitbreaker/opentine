"""Deep repository integrity and event-DAG verification."""

from __future__ import annotations

import os
import re
import stat
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from opentine.kernel import KernelError, ObjectEnvelope, parse_oid, verify_object
from opentine.repository._annotations import validate_annotation_chain
from opentine.repository._paths import internal_path
from opentine.repository._refs import validate_ref_target
from opentine.repository._run_graph import validate_event_metrics, validate_run_graph
from opentine.repository._semantic_view import SemanticView
from opentine.repository.pack import MAX_PACK_BYTES, inspect_pack

if TYPE_CHECKING:
    from opentine.repository.store import Repo

_PACK_NAME = re.compile(r"^([0-9a-f]{64})\.pack$")
_MAX_FSCK_PACKS = 1_000
_MAX_FSCK_PACK_BYTES = 1024 * 1024 * 1024


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


def _pack_errors(repo: Repo) -> list[str]:
    errors: list[str] = []
    directory = internal_path(repo.path, "packs")
    total = 0
    try:
        with os.scandir(directory) as stream:
            names = []
            for entry in stream:
                names.append(entry.name)
                if len(names) > _MAX_FSCK_PACKS:
                    raise KernelError("pack count exceeds the fsck verification limit")
    except (KernelError, OSError) as exc:
        return [f"packs: {exc}"]
    for name in sorted(names):
        match = _PACK_NAME.fullmatch(name)
        if not match:
            errors.append(f"pack {name}: invalid pack filename")
            continue
        try:
            path = internal_path(repo.path, "packs", name)
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise KernelError("stored pack is not a private regular file")
                total += info.st_size
                if info.st_size > MAX_PACK_BYTES or total > _MAX_FSCK_PACK_BYTES:
                    raise KernelError("stored packs exceed the fsck verification byte limit")
                with os.fdopen(fd, "rb") as handle:
                    fd = -1
                    data = handle.read(MAX_PACK_BYTES + 1)
            finally:
                if fd >= 0:
                    os.close(fd)
            pack_id, objects, _ = inspect_pack(data)
            if pack_id != f"sha256:{match.group(1)}":
                raise KernelError("pack filename does not match its verified id")
            for oid, raw in objects:
                if repo.raw(oid) != raw:
                    raise KernelError(f"packed object does not match loose object: {oid}")
        except (KeyError, KernelError, OSError) as exc:
            errors.append(f"pack {name}: {exc}")
    return errors


def fsck(repo: Repo, *, deep: bool = True) -> FsckResult:
    errors: list[str] = []
    view = SemanticView(repo)
    oids = repo.iter_oids()
    try:
        for oid in repo.shallow_oids():
            parse_oid(oid)
    except (KernelError, OSError, UnicodeError) as exc:
        errors.append(f"shallow: {exc}")
    for oid in oids:
        try:
            verify_object(repo.raw(oid), oid, repo._link_exists if deep else None)
            envelope = ObjectEnvelope.decode(repo.raw(oid), oid)
            validate_annotation_chain(view, envelope)
            validate_event_metrics(envelope)
            if deep and oid.startswith("run:"):
                validate_run_graph(view, envelope)
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
            if not repo.has(oid):
                errors.append(f"ref {name}: missing {oid}")
                continue
            target = view.get(oid)
            validate_ref_target(name, target.object_type, target.payload())
        except (KernelError, ValueError) as exc:
            errors.append(f"ref {name}: {exc}")
            continue
    if deep:
        errors.extend(_pack_errors(repo))
        errors.extend(_cycle_errors(view, oids))
    return FsckResult(not errors, len(oids), len(refs), tuple(errors))
