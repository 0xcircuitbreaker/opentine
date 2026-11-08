"""Benchmark ``opentine-log/1`` appends on a large log (0.45 acceptance: 1M entries, p95 < 10 ms).

Usage: ``uv run python scripts/bench_tlog_append.py [--entries 1000000] [--appends 200]``.
Seeds a signed log of ``--entries`` entries in one pass, then times ``--appends``
single appends through ``_tlog_note.append`` (lock, right-edge check, tile writes,
fsync, signed checkpoint). Exits 1 when p95 exceeds ``--p95-ms``.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

from opentine.repository import _tlog, _tlog_note

ORIGIN = "bench.example/log"


def seed(root: Path, n: int) -> None:
    entries = [f"e{i}".encode() for i in range(n)]
    _tlog.write_tiles(root, entries, 0)
    key = _tlog_note._signer(root, ORIGIN)
    tree = _tlog.merkle_root([_tlog.leaf_hash(e) for e in entries])
    (root / "checkpoint").write_bytes(_tlog_note.sign_checkpoint(key, ORIGIN, n, tree))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entries", type=int, default=1_000_000)
    parser.add_argument("--appends", type=int, default=200)
    parser.add_argument("--p95-ms", type=float, default=10.0)
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp, "log")
        seed(root, args.entries)
        times = []
        for i in range(args.appends):
            start = time.perf_counter()
            _tlog_note.append(root, ORIGIN, lambda _t, i=i: f"n{i}".encode())
            times.append((time.perf_counter() - start) * 1000)
    times.sort()
    report = {
        "appends": args.appends,
        "entries": args.entries,
        "p50_ms": round(times[len(times) // 2], 3),
        "p95_ms": round(times[min(len(times) - 1, int(len(times) * 0.95))], 3),
        "max_ms": round(times[-1], 3),
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["p95_ms"] < args.p95_ms else 1


if __name__ == "__main__":
    sys.exit(main())
