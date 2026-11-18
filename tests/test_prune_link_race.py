"""A prune that finishes between a writer's link check and its write (CI flake, 0.48).

``Repo.put`` checks a link is stored, then ``store_envelope`` re-touches it. A
``tine prune --delete`` that moved the object *and* removed its quarantine in
between left the touch finding nothing and no quarantine to consult, so the
non-strict touch let the event be stored naming the pruned blob: fsck failed.
"""

from __future__ import annotations

import os
import time

import pytest

from opentine.kernel import KernelError
from opentine.repository import Repo, _link_touch
from opentine.repository._gc_prune import prune


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")


def _orphan(repo) -> str:
    blob = repo.put("blob", b"orphan referenced by id only")
    stamp = time.time() - 30 * 86400
    os.utime(repo._object_path(blob), (stamp, stamp))
    return blob


def test_a_prune_finishing_after_the_link_check_refuses_the_write(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "r")
    blob = _orphan(repo)
    has = Repo.has

    def has_then_prune(self, oid):
        found = has(self, oid)
        if oid == blob and found:  # the writer saw it; prune now runs to completion
            prune(self, delete=True, min_age=0, git_links=False)
        return found

    monkeypatch.setattr(Repo, "has", has_then_prune)
    with pytest.raises(KernelError, match="missing linked object"):
        repo.put("event", {"kind": "tool", "parent_ids": [], "output_blob": blob})
    monkeypatch.undo()
    check = Repo.open(repo.path)
    assert not check.has(blob)
    assert check.fsck().ok, check.fsck()


def test_a_link_to_an_object_not_stored_yet_is_still_allowed(tmp_path):
    from opentine.kernel import ObjectEnvelope
    from opentine.repository._objects import store_envelope

    repo = Repo.init(tmp_path / "r")
    blob = ObjectEnvelope.create("blob", b"later")
    event = ObjectEnvelope.create(
        "event", {"kind": "tool", "parent_ids": [], "output_blob": blob.oid}
    )
    store_envelope(repo, event)  # a graph stored in any order: the blob comes next
    store_envelope(repo, blob)
    assert repo.has(event.oid) and repo.fsck().ok


@pytest.mark.skipif(
    not (_link_touch._OPENAT and os.utime in os.supports_fd), reason="needs openat-style touch"
)
def test_a_touch_whose_stamp_lands_after_prune_moved_the_object_refuses_the_link(
    tmp_path, monkeypatch
):
    """CI flake, 0.54: ``utimensat`` resolves the name, then stamps the inode.

    The writer's touch found the blob in place; before the stamp landed, prune
    moved it into quarantine, saw it still old, and deleted it. The stamp then
    hit the quarantined inode, the touch reported success, and the event was
    stored naming the pruned blob (fsck: missing linked object).
    """
    repo = Repo.init(tmp_path / "r")
    blob = _orphan(repo)
    utime = os.utime
    raced: list[bool] = []

    def lookup_then_prune_then_stamp(path, *args, dir_fd=None, **kwargs):
        if dir_fd is None or raced:
            return utime(path, *args, dir_fd=dir_fd, **kwargs)
        raced.append(True)
        fd = os.open(path, os.O_RDONLY, dir_fd=dir_fd)  # the name is resolved here
        try:
            prune(repo, delete=True, min_age=0, git_links=False)  # moves, sees it old, deletes
            utime(fd)  # the stamp lands on the inode prune already took
        finally:
            os.close(fd)

    monkeypatch.setattr(os, "utime", lookup_then_prune_then_stamp)
    with pytest.raises(KernelError, match="missing linked object"):
        repo.put("event", {"kind": "tool", "parent_ids": [], "output_blob": blob})
    monkeypatch.undo()
    assert raced
    check = Repo.open(repo.path)
    assert not check.has(blob)
    assert check.fsck().ok, check.fsck()
