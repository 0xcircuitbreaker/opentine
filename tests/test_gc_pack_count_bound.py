"""Many small packs never make object lookups quadratic (0.86.1).

The killed-writer stress loop calls ``gc`` every few runs; each call wrote one
more pack and none merged, so 200 rounds left ~400 packs and every object
lookup (fsck most of all) walked them all: quadratic, past the nightly timeout.
"""

from __future__ import annotations

from opentine import Run, StepKind
from opentine.repository import Repo
from opentine.repository._autopack import MAX_PACKS, pack_sizes
from opentine.repository._gc import gc
from opentine.repository._pack_lazy import MANY_LOOKUPS, MANY_PACKS
from opentine.repository._pack_lookup import LegacyIndex, MappedIndex
from opentine.repository._packs import _CACHE


def test_repeated_gc_merges_small_packs(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    for n in range(3 * MAX_PACKS):
        run = Run(id=f"r{n}", model_info="mock/test")
        run.add_step(StepKind.tool, {"i": n}, {"output": f"out {n} " * 50})
        repo.put_run(run, ref=f"heads/r{n}")
        gc(repo)
        assert len(pack_sizes(repo.path)) <= MAX_PACKS, n
    check = Repo.open(repo.path)
    assert check.fsck().ok
    refs = check.list_refs()
    assert all(f"heads/r{n}" in refs for n in range(3 * MAX_PACKS))
    assert all(check.has(oid) for oid in refs.values())


def test_lookups_across_many_packs_stop_probing_every_index(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "repo")
    for n in range(2 * MANY_PACKS):
        run = Run(id=f"r{n}", model_info="mock/test")
        run.add_step(StepKind.tool, {"i": n}, {"output": f"out {n} " * 50})
        repo.put_run(run, ref=f"heads/r{n}")
        gc(repo, merge_packs=[])  # explicit: no merge, so packs pile up
    packs = len(pack_sizes(repo.path))
    assert packs > MANY_PACKS
    probes = []
    for cls in (LegacyIndex, MappedIndex):
        original = cls.find
        monkeypatch.setattr(
            cls, "find", lambda self, oid, f=original: probes.append(1) or f(self, oid)
        )
    _CACHE.clear()  # a fresh process: no bulk map left over from gc
    check = Repo.open(repo.path)
    assert check.fsck().ok
    # Probing every index per lookup would be ~lookups * packs / 2 (thousands here).
    assert len(probes) <= MANY_LOOKUPS * packs
