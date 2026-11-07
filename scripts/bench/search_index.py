"""Benchmark: a cold 3-term BM25 query over the 0.44 FTS5 search index.

Usage: ``uv run python scripts/bench/search_index.py [--runs 100000] [--queries 200]
[--real 500]``

* synthetic: ``--runs`` rows written straight into ``.tine/index/search.sqlite``
  with the production schema (``_search_index._SCHEMA``), each with a prompt and
  completion of ~200 words drawn Zipf-like from a 20,000-word vocabulary, a tool
  call and a file path. Each query opens a fresh read-only connection (the
  "cold" query a ``tine repo-search`` process makes) and fetches the top 20
  rows by BM25 for three random vocabulary words. Reports p50/p95/max.
* ``--real N``: N runs written through ``Repo.put_run``, then
  ``rebuild`` and end-to-end ``Repo.search`` (which also reads scores from the
  attestation index) against the scan, to show both answer the same.

The ROADMAP target is p95 <= 200 ms on the pinned runner; numbers measured
elsewhere are indicative only.
"""

from __future__ import annotations

import argparse
import json
import random
import sqlite3
import statistics
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from opentine.repository import _search_index  # noqa: E402
from opentine.repository._search_query import ranked_rows  # noqa: E402


def _vocabulary(size: int, rng: random.Random) -> list[str]:
    letters = "abcdefghijklmnopqrstuvwxyz"
    words = {"".join(rng.choices(letters, k=rng.randint(4, 10))) for _ in range(size * 2)}
    return sorted(words)[:size]


def synthesize(root: Path, runs: int, rng: random.Random) -> tuple[Path, list[str]]:
    words = _vocabulary(20_000, rng)
    weights = [1 / (rank + 1) for rank in range(len(words))]
    path = root / "index" / "search.sqlite"
    path.parent.mkdir(parents=True)
    connection = sqlite3.connect(path)
    for statement in _search_index._SCHEMA:
        connection.execute(statement)
    connection.execute("INSERT INTO meta VALUES ('format', ?)", (_search_index.INDEX_FORMAT,))
    for number in range(runs):
        body = " ".join(rng.choices(words, weights, k=200))
        tool = json.dumps({"name": "Bash", "arguments": {"command": rng.choice(words)}})
        file_path = f"src/{rng.choice(words)}/{rng.choice(words)}.py"
        run_id = f"run:sha256:{number:064x}"
        cursor = connection.execute(
            "INSERT INTO runs(run_id, status, models, cost, latency, created_at)"
            " VALUES (?, 'completed', '[\"m\"]', 0.01, 1.0, ?)",
            (run_id, float(number)),
        )
        connection.execute(
            "INSERT INTO docs(rowid, body, tools, paths, meta) VALUES (?, ?, ?, ?, ?)",
            (cursor.lastrowid, body, tool, file_path, f"{run_id} completed m"),
        )
    connection.execute("INSERT INTO docs(docs) VALUES ('optimize')")
    connection.commit()
    connection.close()
    return path, words


def bench_synthetic(runs: int, queries: int, seed: int) -> None:
    rng = random.Random(seed)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        started = time.perf_counter()
        path, words = synthesize(root, runs, rng)
        build = time.perf_counter() - started
        repo = SimpleNamespace(path=root)
        print(
            f"synthetic runs={runs} index={path.stat().st_size / 2**20:.1f} MiB build={build:.1f}s"
        )
        # dense: the 50 most frequent words (long posting lists, the worst case);
        # mixed: the top 2,000 (typical words, many queries match few runs).
        for label, pool in (("dense", words[:50]), ("mixed", words[:2000])):
            timings, hits = [], 0
            for _ in range(queries):
                query = " ".join(rng.sample(pool, 3))
                start = time.perf_counter()
                rows = list(ranked_rows(repo, query, successful_only=True, limit=20) or [])
                timings.append((time.perf_counter() - start) * 1000)
                hits += bool(rows)
            timings.sort()
            p95 = timings[max(0, int(len(timings) * 0.95) - 1)]
            print(
                f"cold 3-term BM25 top-20 ({label}): p50={statistics.median(timings):.1f} ms "
                f"p95={p95:.1f} ms max={timings[-1]:.1f} ms ({hits}/{queries} matched)"
            )


def bench_real(count: int) -> None:
    from opentine.graph import Run, RunStatus, StepKind
    from opentine.repository import Repo

    rng = random.Random(1)
    words = _vocabulary(2000, rng)
    with tempfile.TemporaryDirectory() as directory:
        repo = Repo.init(Path(directory))
        for number in range(count):
            run = Run(run_id=f"r{number}", model_info="m", status=RunStatus.completed)
            run.add_step(StepKind.model, {"prompt": " ".join(rng.choices(words, k=50))}, {})
            repo.put_run(run)
        started = time.perf_counter()
        _search_index.rebuild(repo)
        print(f"real runs={count} rebuild={time.perf_counter() - started:.2f}s")
        query = " ".join(words[:1])
        for label, use_index in (("index", True), ("scan", False)):
            start = time.perf_counter()
            found = repo.search(query, limit=1000, use_index=use_index)
            elapsed = (time.perf_counter() - start) * 1000
            print(f"  {label}: {len(found)} runs in {elapsed:.1f} ms")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--runs", type=int, default=100_000)
    parser.add_argument("--queries", type=int, default=200)
    parser.add_argument("--seed", type=int, default=44)
    parser.add_argument("--real", type=int, default=0, help="Also bench N real put_run runs")
    args = parser.parse_args()
    if not _search_index.fts5_available():
        print("this Python's sqlite3 lacks FTS5; nothing to measure")
        return 1
    bench_synthetic(args.runs, args.queries, args.seed)
    if args.real:
        bench_real(args.real)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
