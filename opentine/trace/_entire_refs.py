"""Finding Entire checkpoints: per-checkpoint refs first, the v1 branch as fallback.

Current entireio/cli (its git-refs backend, ``checkpoint/refs_naming.go``) keeps
one ref per checkpoint, ``refs/entire/checkpoints/<shard>/<id>`` where
``<shard>`` is the id's *last* two characters. Each ref names a commit whose
tree root *is* the checkpoint (``metadata.json``, ``0/``, ``1/`` ...), so the
summary lists sessions as ``/<N>/metadata.json``. Older CLIs, and checkpoints
not yet migrated, live on the single ``entire/checkpoints/v1`` branch under
``<id[:2]>/<id[2:]>/`` (see :mod:`opentine.trace._entire_git`). A checkpoint
present in both resolves to its ref, as Entire's own read routing does once a
checkpoint has been copied out of the branch.

A :class:`Location` says where one checkpoint's tree is: the ref to read and
the path of the checkpoint inside it (``""`` at a ref's root).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

from opentine._git_link import GitLinkError, git
from opentine.trace import _entire_git as eg

REF_PREFIX = "refs/entire/checkpoints/"
MAX_REFS = 10_000


class Location(NamedTuple):
    checkpoint: str
    ref: str
    base: str


def ref_name(checkpoint: str) -> str:
    """The per-checkpoint ref Entire writes for *checkpoint*."""
    if not eg.CHECKPOINT_ID.fullmatch(checkpoint):
        raise eg.EntireError(f"not a checkpoint id: {checkpoint[:40]!r}")
    return f"{REF_PREFIX}{checkpoint[-2:]}/{checkpoint}"


def parse_ref(name: str) -> str | None:
    """The checkpoint id of a well-formed checkpoint ref, else ``None``.

    The tail must be exactly ``<shard>/<id>`` with the shard matching the id's
    last two characters case-insensitively (Entire's ``ParseRef``).
    """
    tail = name.removeprefix(REF_PREFIX)
    if tail == name or tail.count("/") != 1:
        return None
    shard, checkpoint = tail.split("/")
    if not eg.CHECKPOINT_ID.fullmatch(checkpoint) or shard.lower() != checkpoint[-2:].lower():
        return None
    return checkpoint


def ref_locations(repo: Path) -> list[Location]:
    """Every per-checkpoint ref, most recently committed first."""
    try:
        listed = git(
            repo,
            "for-each-ref",
            "--sort=-committerdate",
            f"--count={MAX_REFS}",
            "--format=%(refname)",
            REF_PREFIX,
        )
    except GitLinkError:
        return []
    found = []
    for name in listed.splitlines():
        checkpoint = parse_ref(name.strip())
        if checkpoint:
            found.append(Location(checkpoint, name.strip(), ""))
    return found


def _branch_ref(repo: Path) -> str | None:
    try:
        return eg.find_ref(repo)
    except eg.EntireError:
        return None


def branch_locations(repo: Path, ref: str) -> list[Location]:
    """Every checkpoint on the v1 branch, newest-written first."""
    ids = eg.checkpoint_ids(repo, ref)
    try:
        newest = eg.newest_checkpoint(repo, ref)
    except eg.EntireError:
        newest = None
    ordered = ([newest] if newest in ids else []) + [item for item in ids if item != newest]
    return [Location(item, ref, eg.checkpoint_path(item)) for item in ordered]


def all_locations(repo: Path) -> list[Location]:
    """Every checkpoint the repository holds, refs first, each id once."""
    found = ref_locations(repo)
    seen = {item.checkpoint for item in found}
    branch = _branch_ref(repo)
    if branch:
        found += [item for item in branch_locations(repo, branch) if item.checkpoint not in seen]
    if not found:
        raise eg.EntireError(
            f"no {REF_PREFIX}* refs and no {eg.BRANCH} branch in {repo} (is Entire enabled there?)"
        )
    return found


def locate(repo: Path, wanted: str | None) -> Location:
    """*wanted* (an id or unique prefix), or the newest checkpoint."""
    if wanted and not re.fullmatch(r"[0-9A-Za-z]{1,26}", wanted):
        raise eg.EntireError(f"not a checkpoint id: {wanted[:40]!r}")
    found = all_locations(repo)
    if not wanted:
        return found[0]
    matches = [item for item in found if item.checkpoint.startswith(wanted)]
    if len(matches) != 1:
        problem = "matches no checkpoint" if not matches else "is ambiguous"
        raise eg.EntireError(f"checkpoint {wanted!r} {problem}")
    return matches[0]


__all__ = ["REF_PREFIX", "Location", "all_locations", "locate", "parse_ref", "ref_name"]
