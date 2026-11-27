"""Repeated plain ``gc`` keeps the pack count bounded (nightly Windows stress, 0.86).

Each ``gc`` that finds a loose object writes a new pack. Without folding the
small packs back in, 8 workers x 200 gc rounds left >500 packs (>1000 files)
and fsck failed with "pack count exceeds the fsck verification limit".
"""

from __future__ import annotations

from opentine.repository import Repo
from opentine.repository._autopack import MAX_PACKS, pack_sizes
from opentine.repository._gc import gc


def test_repeated_gc_folds_small_packs_and_keeps_every_object(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    written = []
    for i in range(40):
        oid = repo.put("blob", f"pack-count {i}".encode("ascii"))
        repo.update_ref(f"tags/p{i}", oid)
        written.append(oid)
        gc(repo, min_age=0)
        assert len(pack_sizes(repo.path)) <= MAX_PACKS + 1
    reopened = Repo.open(repo.path)
    for oid in written:
        assert reopened.get(oid).body.startswith(b"pack-count ")
    assert reopened.fsck().ok


def test_explicit_empty_merge_list_still_merges_nothing(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    for i in range(MAX_PACKS + 3):
        repo.put("blob", f"keep {i}".encode("ascii"))
        gc(repo, min_age=0, merge_packs=[])
    assert len(pack_sizes(repo.path)) == MAX_PACKS + 3
