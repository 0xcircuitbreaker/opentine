"""Benchmark the ``tine transcripts`` index on synthetic transcripts (0.74 acceptance).

Usage: ``uv run python scripts/bench/transcripts_index.py [--transcripts 100000]
[--workers 4] [--queries 40] [--real 300] [--out FILE.json]``.

Three parts, timed separately:

* **embed and write**: ``--transcripts`` synthetic transcripts from the seeded
  corpus generator (``tests/transcript_corpus.py``; 8 planted behaviours in
  ``--transcripts // 1000`` runs each), embedded with ``transcript-hash/1``
  in ``--workers`` processes and written through
  :func:`opentine._transcript_index.write`, the staged write a rebuild uses.
* **search**: ``--queries`` exact top-50 searches from seeded runs over the
  whole index, with the seeded-behaviour recall at top 50.
* **object reading**: ``--real`` runs stored with ``Repo.put_run`` and a full
  index build over them, giving a per-run extraction cost that extrapolates
  to ``--transcripts`` (storing 100k real runs takes far longer than indexing
  them, so they are not created here).

Target (docs/TRANSCRIPTS.md): 100k transcripts indexed in under 30 minutes on
an 8-core CPU. Results go to docs/bench/0.73-transcripts.md; no test asserts
a duration.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from opentine import _transcript_embed as te  # noqa: E402
from opentine import _transcript_index as ti  # noqa: E402
from opentine._transcript_text import Transcript  # noqa: E402
from tests import transcript_corpus as tc  # noqa: E402


def _job(rows: list[dict]) -> list[tuple]:
    docs = [Transcript(r["name"], tc.render(r), len(r["steps"]), False) for r in rows]
    return ti.text_rows(docs, te.HashBackend())


def embed_and_write(rows: list[dict], workers: int, out: Path) -> dict:
    pieces = [rows[i : i + 1000] for i in range(0, len(rows), 1000)]
    start = time.perf_counter()
    with ProcessPoolExecutor(max_workers=workers) as pool:
        truncated = ti.write(out, pool.map(_job, pieces), {"format": ti.FORMAT})
    seconds = time.perf_counter() - start
    return {"transcripts": len(rows), "workers": workers, "seconds": round(seconds, 2),
            "ms_per_transcript": round(1000 * seconds / len(rows), 3),
            "index_bytes": out.stat().st_size, "truncated": truncated}  # fmt: skip


def search(rows: list[dict], path: Path, queries: int) -> dict:
    start = time.perf_counter()
    index, _, _ = ti.load(path)
    load_s = time.perf_counter() - start
    labels = {r["name"]: r["behaviour"] for r in rows}
    seeded = [n for n, lab in sorted(labels.items()) if lab]
    seeded = seeded[:: max(1, len(seeded) // queries)][:queries]
    found = total = 0
    times = []
    for name in seeded:
        others = {n for n, lab in labels.items() if lab == labels[name]} - {name}
        start = time.perf_counter()
        hits = index.search(index.vectors[index.runs.index(name)], 50, exclude=name)["hits"]
        times.append(time.perf_counter() - start)
        found += len({h["run"] for h in hits} & others)
        total += min(len(others), 50)
    times.sort()
    return {"load_seconds": round(load_s, 2), "queries": len(seeded),
            "median_query_seconds": round(times[len(times) // 2], 3),
            "recall_at_50": round(found / total, 4)}  # fmt: skip


def real(count: int, workers: int) -> dict:
    from opentine.repository import Repo

    with tempfile.TemporaryDirectory() as base:
        repo = Repo.init(Path(base) / "r")
        tc.write(repo, tc.specs(n=count, per_behaviour=count // 40, seed=5))
        out = {}
        for label, n in (("serial", 1), (f"{workers} workers", workers)):
            (ti.index_path(repo.path)).unlink(missing_ok=True)
            start = time.perf_counter()
            ti.build(repo, workers=n)
            out[label] = round(1000 * (time.perf_counter() - start) / count, 3)
        return {"runs": count, "ms_per_run": out}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--transcripts", type=int, default=100_000)
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--queries", type=int, default=40)
    parser.add_argument("--real", type=int, default=300)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        import numpy

        numpy_version = numpy.__version__
    except ImportError:
        numpy_version = None
    rows = tc.specs(n=args.transcripts, per_behaviour=max(2, args.transcripts // 1000))
    with tempfile.TemporaryDirectory() as base:
        path = Path(base) / "index.sqlite"
        result = {"hardware": {"cpus": os.cpu_count(), "machine": platform.machine(),
                               "processor": platform.processor() or None,
                               "python": platform.python_version(), "numpy": numpy_version},
                  "backend_digest": te.backend_digest(te.HashBackend()),
                  "embed_and_write": embed_and_write(rows, args.workers, path),
                  "search": search(rows, path, args.queries)}  # fmt: skip
    if args.real:
        result["object_reading"] = real(args.real, args.workers)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_bytes(text.encode("utf-8"))
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
