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
ids are recorded here and the fallback skips them -- as are annotations a pack
plants for a run it does not carry, ahead of that run's arrival. ``fetch`` adopts
the advertised annotation refs of the runs it brought; for runs that were already
here it keeps them under ``remotes/<name>/annotations/`` unless the owner opts in.
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
#: One record line: ``annotation:sha256:<64 hex>\n``. The byte limit follows the
#: count limit, so no record the writer accepts is one the reader refuses.
_LINE_BYTES = len("annotation:sha256:") + 64 + 1


class Unadopted(frozenset):
    """The recorded ids; ``complete`` is False when the record could not be fully read.

    An incomplete record cannot say which annotations are foreign, so the fallback
    adopts nothing and new foreign annotations are not installed -- never a failed
    ``load_run``, ``put_run`` or fetch. ``tine fsck`` reports the damage.
    """

    complete = True


def _incomplete(oids=()) -> Unadopted:
    record = Unadopted(oids)
    record.complete = False
    return record


def _path(root: Path) -> Path:
    return internal_path(root, "unadopted")


def read_unadopted(root: Path, *, strict: bool = False) -> Unadopted:
    """The record; with *strict*, damage raises (fsck) instead of reading as incomplete."""
    max_bytes = MAX_UNADOPTED * _LINE_BYTES
    try:
        fd = os.open(_path(root), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return Unadopted()
    except OSError as exc:
        if strict:
            raise KernelError("unadopted annotation record cannot be safely read") from exc
        return _incomplete()
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(max_bytes + 1)
    problem = None
    if len(data) > max_bytes:
        problem = "unadopted annotation record exceeds its byte limit"
        data = data[: data.rfind(b"\n", 0, max_bytes) + 1]
    lines = [line for line in data.decode("ascii", "replace").split("\n") if line]
    valid = []
    for oid in lines:
        try:
            if parse_oid(oid)[0] == "annotation":
                valid.append(oid)
                continue
        except (KernelError, ValueError):
            pass
        problem = problem or "unadopted annotation record lists a non-annotation"
    if problem is None:
        return Unadopted(valid)
    if strict:
        raise KernelError(problem)
    return _incomplete(valid)


def record_unadopted(root: Path, oids: Iterable[str], repo=None) -> set[str]:
    """Record *oids*; return the ones that did not fit, which must not be installed.

    The record never grows past its limit (it used to, and then every later read
    failed). When full it first forgets entries the fallback can no longer read;
    what still does not fit is handed back for the install to leave out, so a
    foreign annotation is either recorded or absent -- never adoptable.
    """
    new = set(oids)
    if not new:
        return set()
    current = read_unadopted(root)
    if not current.complete:
        return new
    new -= current
    if not new:
        return set()
    kept = set(current)
    if len(kept) + len(new) > MAX_UNADOPTED and repo is not None:
        from opentine.repository._association_index import still_needed

        kept = still_needed(repo, kept)
    room = max(0, MAX_UNADOPTED - len(kept))
    accepted = set(sorted(new)[:room])
    if accepted or len(kept) < len(current):
        body = "\n".join(sorted(kept | accepted)) + "\n"
        atomic_bytes(_path(root), body.encode("ascii"))
    return new - accepted


def foreign_annotations(repo, view, objects: list[tuple[str, bytes]]) -> list[str]:
    """Incoming annotations no ref vouches for and whose run this pack did not bring.

    Called before anything is written, so "already had" means before this pack.
    An annotation is the pack's own only when its target run arrives in the same
    pack and was not here before: one aimed at a run held already, or at a run
    the pack does not carry at all (a shallow boundary -- planted ahead of the
    run's arrival), is recorded. A run with an annotation ref is left out: the
    fallback never reads it. An annotation held before this pack is not judged
    again -- it is in the record already, or the fallback adopted it -- so a
    remote that re-sends one cannot un-adopt it.
    """
    from opentine.repository._annotations import annotation_ref

    packed_runs = {oid for oid, _ in objects if oid.startswith("run:")}
    foreign = []
    for oid, _ in objects:
        if not oid.startswith("annotation:") or repo.has(oid):
            continue
        target = view.get(oid).payload().get("target_id")
        if not isinstance(target, str) or not target.startswith("run:"):
            continue
        brought = target in packed_runs and not repo.has(target)
        if not brought and not repo.read_ref(annotation_ref(target)):
            foreign.append(oid)
    return foreign


# Re-exported: fetch and the tests import these from here.
from opentine.repository._annotation_adopt import (  # noqa: E402
    adopt_advertised_annotations,
    runs_held,
)

__all__ = [
    "MAX_UNADOPTED",
    "Unadopted",
    "adopt_advertised_annotations",
    "foreign_annotations",
    "read_unadopted",
    "record_unadopted",
    "runs_held",
]
