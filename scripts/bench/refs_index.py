"""Micro-benchmark: ``list_refs`` (loose vs packed-refs) and a cold pack-index load.

Usage: ``uv run python scripts/bench/refs_index.py [--refs N] [--objects N]``

* ``list_refs``: N loose ref files, then the same refs after ``tine gc
  --pack-refs`` (one ``packed-refs`` read).
* cold index: a fresh process state (pack cache cleared) answering one
  ``has()``; "eager" is what 0.36 did on its first lookup (parse every index
  entry into one ``oid -> place`` dict), "lazy" is the 0.37 mapped index.

Numbers are wall-clock medians of a few runs on whatever machine runs this;
they are indicative only (ROADMAP §3: the pinned runner re-measures them).
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from opentine.kernel import ObjectEnvelope  # noqa: E402
from opentine.repository import Repo, _gc_refs, _packed_refs, _packs  # noqa: E402
from opentine.repository._config import STORAGE_V3, rewrite_config  # noqa: E402
from opentine.repository._gc import gc  # noqa: E402
from opentine.repository._pack_write import write_pack  # noqa: E402
from opentine.repository._packs import load_index  # noqa: E402


def _median(action, runs: int = 5) -> float:
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        action()
        times.append(time.perf_counter() - start)
    return statistics.median(times)


def bench_refs(root: Path, count: int) -> dict[str, float]:
    repo = Repo.init(root / "refs", compression="zlib")
    target = repo.put("run", {"events": [], "manifests": {}, "roots": [], "tips": []})
    names = [f"tags/t{index:07}" for index in range(count)]
    for start in range(0, count, 4096):
        repo.update_refs([(name, target, None) for name in names[start : start + 4096]])
    loose = _median(repo.list_refs)
    _gc_refs.enable(repo)
    gc(repo)
    _packed_refs._CACHE.clear()
    cold = _median(lambda: (_packed_refs._CACHE.clear(), repo.list_refs()))
    assert len(repo.list_refs()) == count
    return {"list_refs_loose_s": loose, "list_refs_packed_cold_s": cold}


def bench_index(root: Path, count: int) -> dict[str, float]:
    repo = Repo.init(root / "index", compression="zlib")
    rewrite_config(repo.path, lambda config: config.update(version=STORAGE_V3) or True)
    objects = []
    for index in range(count):
        envelope = ObjectEnvelope.create("blob", os.urandom(16) + index.to_bytes(8, "big"))
        objects.append((envelope.oid, envelope.encode()))
    objects.sort()
    digest = write_pack(repo.path, objects, "zlib", 1, 3)
    probe = objects[count // 2][0]

    def eager() -> None:  # 0.36: every entry parsed into one dict at the first lookup
        _, entries, _ = load_index(repo.path, digest)
        where = {oid: (digest, *place[:3]) for oid, place in entries.items()}
        assert probe in where

    def lazy() -> None:
        _packs._CACHE.clear()
        assert Repo(repo.path).has(probe)

    return {"index_cold_eager_s": _median(eager, 3), "index_cold_lazy_s": _median(lazy, 3)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--refs", type=int, default=10_000)
    parser.add_argument("--objects", type=int, default=200_000)
    args = parser.parse_args()
    os.environ.setdefault("OPENTINE_AUTO_PACK", "0")
    with tempfile.TemporaryDirectory() as directory:
        results = {
            "refs": args.refs,
            "objects": args.objects,
            **bench_refs(Path(directory), args.refs),
            **bench_index(Path(directory), args.objects),
        }
    for key, value in results.items():
        print(f"{key:28} {value:.4f}" if isinstance(value, float) else f"{key:28} {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
