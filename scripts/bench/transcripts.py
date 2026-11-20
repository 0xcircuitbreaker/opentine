"""Benchmark transcript analysis at corpus scale (0.74 acceptance).

Usage: ``python scripts/bench/transcripts.py [--transcripts 100000]
[--cluster 10000] [--k 16] [--out FILE.json]``.

Three parts, timed separately, over synthetic transcripts from the seeded
generator (``scripts/gen_transcript_corpus.py``, seeds after the committed
corpus, 15% seeded behaviours):

* **index**: fitting the ``opentine.tfidf-hash/1`` space (features, IDF, one
  sparse vector per transcript, the corpus mean) over ``--transcripts``.
* **similarity**: one "find runs like these" query (5 exemplars, top 50) over
  the whole space, and per seeded behaviour the share of the top 50 that has
  it (precision@50: with thousands of seeded runs, recall@50 is bounded by 50).
* **clustering**: seeded k-means with ``--k`` clusters over the first
  ``--cluster`` transcripts.

Reading text out of a repository is not part of it: that cost is the search
index's extraction, measured in docs/bench/0.65-query.md. Acceptance (plan
0.74): 100k transcripts indexed in under 30 minutes, hardware recorded with
the result. No test asserts a duration; results are in
docs/bench/0.74-transcripts.md.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from opentine._transcript_cluster import kmeans, similar  # noqa: E402
from opentine._transcript_embed import Space, backend_digest  # noqa: E402
from scripts.gen_transcript_corpus import SEEDED, transcript  # noqa: E402


def synthetic(n: int, seed: int = 75) -> tuple[dict[str, str], dict[str, str]]:
    rng = random.Random(seed)
    texts, behaviours = {}, {}
    names = list(SEEDED)
    for i in range(n):
        kind = names[i % 3] if rng.random() < 0.15 else "none"
        texts[f"b{i:07d}"], behaviours[f"b{i:07d}"] = transcript(rng, kind), kind
    return texts, behaviours


def _cpu() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_bytes().decode().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transcripts", type=int, default=100_000)
    parser.add_argument("--cluster", type=int, default=10_000)
    parser.add_argument("--k", type=int, default=16)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    texts, behaviours = synthetic(args.transcripts)
    start = time.perf_counter()
    space = Space(texts)
    index_s = time.perf_counter() - start
    start = time.perf_counter()
    similar(space, sorted(i for i, b in behaviours.items() if b == "test-deletion")[:5], 50)
    query_s = time.perf_counter() - start
    precision = {}
    for name in SEEDED:
        seeded = sorted(i for i, b in behaviours.items() if b == name)
        top = similar(space, seeded[:5], 50)
        precision[name] = sum(behaviours[r["run"]] == name for r in top) / 50
    small = Space({i: texts[i] for i in sorted(texts)[: args.cluster]})
    start = time.perf_counter()
    clusters = kmeans(small, args.k, seed=0)
    cluster_s = time.perf_counter() - start
    result = {
        "backend_digest": backend_digest(),
        "transcripts": args.transcripts,
        "bytes": sum(len(t.encode("utf-8")) for t in texts.values()),
        "index_seconds": round(index_s, 2),
        "query_seconds": round(query_s, 2),
        "precision_at_50": precision,
        "cluster": {"transcripts": args.cluster, "k": clusters["k"],
                    "iterations": clusters["iterations"], "seconds": round(cluster_s, 2)},
        "hardware": {"cpu": _cpu(), "cores": os.cpu_count(), "machine": platform.machine(),
                     "python": platform.python_version(), "system": platform.system()},
    }  # fmt: skip
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_bytes(text.encode("utf-8"))
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
