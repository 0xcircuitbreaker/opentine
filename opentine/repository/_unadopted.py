"""Annotations a pack delivered for a run this repository already held.

A run's annotation head is its ``annotations/<digest>`` ref. Annotations with no
ref are still read, by a fallback that adopts the run's unique unheaded chain,
because a clone has always relied on it: ``fetch`` names only the branch tip's
annotation, so every ancestor run's tags and metadata arrive unheaded. That
fallback could not tell those apart from an annotation a pack *added* to a run
already here -- a writer to a shared remote, or anyone handing over a pack,
could attach "approved" tags and a "reviewed by" note to an untagged local run,
with fsck still green.

The difference is visible at install time, and only then: a pack that brings a
run brings that run's annotations with it, while one that annotates a run the
repository already had is asserting something no ref vouches for. Those object
ids are recorded here and the fallback skips them. A ref still adopts them --
``fetch`` fast-forwards every annotation ref the remote advertises -- so a real
update to an old run arrives through the remote's refs, not by object presence.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from opentine.kernel import KernelError, parse_oid
from opentine.repository._paths import atomic_bytes, internal_path

#: The fallback scans at most this many annotations, so the record of ones it
#: must skip never needs to be longer.
MAX_UNADOPTED = 100_000
_MAX_BYTES = MAX_UNADOPTED * 80


def _path(root: Path) -> Path:
    return internal_path(root, "unadopted")


def read_unadopted(root: Path) -> frozenset[str]:
    try:
        fd = os.open(_path(root), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return frozenset()
    except OSError as exc:
        raise KernelError("unadopted annotation record cannot be safely read") from exc
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(_MAX_BYTES + 1)
    if len(data) > _MAX_BYTES:
        raise KernelError("unadopted annotation record exceeds its byte limit")
    try:
        lines = [line for line in data.decode("ascii").split("\n") if line]
    except UnicodeDecodeError as exc:
        raise KernelError("unadopted annotation record must be ASCII") from exc
    for oid in lines:
        if parse_oid(oid)[0] != "annotation":
            raise KernelError("unadopted annotation record lists a non-annotation")
    return frozenset(lines)


def record_unadopted(root: Path, oids: Iterable[str]) -> None:
    new = set(oids)
    if not new:
        return
    merged = read_unadopted(root) | new
    if len(merged) > MAX_UNADOPTED:
        raise KernelError("unadopted annotation record exceeds its object limit")
    atomic_bytes(_path(root), ("\n".join(sorted(merged)) + "\n").encode("ascii"))


def foreign_annotations(repo, view, objects: list[tuple[str, bytes]]) -> list[str]:
    """Incoming annotations that target a run *repo* already had, with no ref.

    Called before anything is written, so "already had" means before this pack.
    A run with an annotation ref is left out: the fallback never reads it.
    """
    from opentine.repository._annotations import annotation_ref

    foreign = []
    for oid, _ in objects:
        if not oid.startswith("annotation:"):
            continue
        target = view.get(oid).payload().get("target_id")
        if not isinstance(target, str) or not target.startswith("run:"):
            continue
        if repo.has(target) and not repo.read_ref(annotation_ref(target)):
            foreign.append(oid)
    return foreign


def _fast_forward(repo, old: str | None, new: str) -> bool:
    from opentine.repository.pack import MAX_PACK_OBJECTS

    current = new
    for _ in range(MAX_PACK_OBJECTS):
        if current == old or old is None:
            return True
        previous = repo.get(current).payload().get("previous_id")
        if not isinstance(previous, str):
            return False
        current = previous
    return False


def adopt_advertised_annotations(repo, remote_refs: dict[str, str]) -> None:
    """Fast-forward every run's annotation ref the remote advertises.

    Not only the fetched tip's: an annotation that arrives for a run already
    here is no longer adopted by object presence, so an old run's real update
    must arrive named. A ref that is mis-bound, or whose chain is cut by a
    shallow boundary, leaves that run's head as it was.
    """
    for name, remote in sorted(remote_refs.items()):
        if not name.startswith("annotations/") or not repo.has(remote):
            continue
        local = repo.read_ref(name)
        if local == remote:
            continue
        try:
            if _fast_forward(repo, local, remote):
                repo.update_ref(name, remote, expected_old=local)
        except (KeyError, ValueError):
            continue
