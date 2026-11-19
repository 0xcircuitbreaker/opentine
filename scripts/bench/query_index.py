"""Benchmark the ``tine query`` index on a synthetic repository (0.65 acceptance).

Usage: ``uv run python scripts/bench/query_index.py [--runs 1000000] [--steps 3]
[--real 2000] [--out FILE.json]``.

Two parts, timed separately:

* **index write**: ``--runs`` synthetic runs with ``--steps`` steps each, plus
  one monitor verdict and one eval verdict per 10 runs, written through
  :func:`opentine._query_index.write` (the same staged write a rebuild does),
  then five typical aggregate queries through the read-only executor.
* **object reading**: ``--real`` runs stored with ``Repo.put_run`` and a full
  ``tine query index --rebuild`` over them, giving a per-run read cost that
  extrapolates to ``--runs`` (writing a million real runs takes far longer
  than indexing them, so they are not created here).

Acceptance (docs/QUERY.md): a 1e6-run build under 10 minutes, a typical
aggregate under 2 s. The numbers are recorded in docs/bench/0.65-query.md;
no test asserts a duration.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
import time
from pathlib import Path

from opentine import _query_index as qi
from opentine._query_sql import run

QUERIES = {
    "cost by model": "SELECT model, COUNT(*) AS steps, SUM(cost) AS total FROM costs "
    "GROUP BY model",
    "runs per status": "SELECT status, COUNT(*) AS n FROM runs GROUP BY status",
    "top 10 costly runs": "SELECT run AS oid, SUM(cost) AS total FROM steps GROUP BY run "
    "ORDER BY total DESC LIMIT 10",
    "monitor actions": "SELECT action, COUNT(*) AS n FROM monitor_verdicts GROUP BY action",
    "eval pass rate": "SELECT eval, AVG(passed) AS rate, COUNT(*) AS n FROM evals GROUP BY eval",
}


def _hex(i: int, salt: str) -> str:
    return f"{salt}{i:062x}"[-64:]


def tables(runs: int, steps: int) -> dict:
    models = ("model-a", "model-b", "model-c", "model-d")
    statuses = ("completed", "failed", "running")

    def run_rows():
        for i in range(runs):
            yield (f"run:sha256:{_hex(i, 'a')}", statuses[i % 3], models[i % 4],
                   1.7e9 + i, steps, f"r{i}")  # fmt: skip

    def step_rows():
        for i in range(runs):
            run_oid = f"run:sha256:{_hex(i, 'a')}"
            for s in range(steps):
                yield (f"event:sha256:{_hex(i * steps + s, 'b')}", run_oid, s,
                       "model" if s % 2 == 0 else "tool", models[i % 4], "p", 0.001 * (s + 1),
                       0.5, 1.7e9 + i, 100, 20, 0)  # fmt: skip

    def verdict_rows():
        for i in range(0, runs, 10):
            yield (f"attestation:sha256:{_hex(i, 'c')}", f"run:sha256:{_hex(i, 'a')}",
                   "sha256:" + "1" * 64, 1, "rule-1", f"s{i}", "shell",
                   ("allow", "flag", "block")[i % 3], 0.5, 0.7, 0, "advisory", "monitor",
                   "2026-12-01T00:00:00Z")  # fmt: skip

    def eval_rows():
        for i in range(0, runs, 10):
            yield (f"sha256:{_hex(i, 'd')}", "bench/verdicts.jsonl", i // 10 + 1,
                   f"sha256:{_hex(i % 50, 'e')}", "sha256:" + "2" * 64, f"item-{i}",
                   f"run:sha256:{_hex(i, 'a')}", "exact", 1.0, 0.5, i % 2, "sha256:" + "3" * 64,
                   1, "2026-12-01T00:00:00Z")  # fmt: skip

    return {"runs": run_rows(), "steps": step_rows(), "monitor_verdicts": verdict_rows(),
            "evals": eval_rows()}  # fmt: skip


def real(base: Path, n: int, steps: int) -> dict:
    """Store *n* real runs, then time a rebuild read serially and in parallel."""
    from opentine._query_build import build
    from opentine.graph import Run, StepKind
    from opentine.repository import Repo

    repo = Repo.init(base / "real")
    for i in range(n):
        item = Run(id=f"r{i}", model_info="m")
        for s in range(steps):
            item.add_step(StepKind.model, {"q": i, "s": s}, {"a": i}, cost=0.01)
        repo.put_run(item)
    out: dict = {"runs": n, "steps_per_run": steps, "workers": os.cpu_count() or 1}
    for name, workers in (("serial", 1), ("parallel", out["workers"])):
        start = time.perf_counter()
        counts = build(repo, workers=workers)["counts"]
        seconds = time.perf_counter() - start
        assert counts["runs"] == n and counts["steps"] == n * steps
        out[name] = {"seconds": round(seconds, 2),
                     "per_run_ms": round(1000 * seconds / max(n, 1), 3)}  # fmt: skip
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=1_000_000)
    parser.add_argument("--steps", type=int, default=3)
    parser.add_argument("--real", type=int, default=2000)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="tine-query-bench-") as tmp:
        path = Path(tmp) / "index.sqlite"
        start = time.perf_counter()
        counts = qi.write(path, [tables(args.runs, args.steps)], {"bench": "synthetic"})
        build_s = time.perf_counter() - start
        timings = {}
        for name, sql in QUERIES.items():
            start = time.perf_counter()
            run(path, sql, limit=100, max_steps=10**9)
            timings[name] = round(time.perf_counter() - start, 3)
        result = {"runs": args.runs, "counts": counts, "index_bytes": path.stat().st_size,
                  "write_seconds": round(build_s, 1), "query_seconds": timings,
                  "object_reading": real(Path(tmp), args.real, args.steps) if args.real else None,
                  "python": platform.python_version(), "machine": platform.machine()}  # fmt: skip
    if result["object_reading"]:
        per_run = result["object_reading"]["parallel"]["per_run_ms"] / 1000
        result["extrapolated_rebuild_seconds"] = round(build_s + per_run * args.runs, 1)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    sys.stdout.write(text)
    if args.out:
        args.out.write_bytes(text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
