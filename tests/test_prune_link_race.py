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
from opentine.repository import Repo
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
