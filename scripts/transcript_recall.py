"""Seeded-behaviour recall@50 on the committed transcript corpus (0.74).

    python scripts/transcript_recall.py [CORPUS.jsonl] [--k 50] [--exemplars 5]

Prints the per-behaviour counts and recall as JSON and exits 1 when any
behaviour's recall is below 0.9 (the 0.74 acceptance). Count based and
deterministic; tests/test_074_transcript_cluster.py asserts the same.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from opentine._transcript_cluster import recall_at  # noqa: E402
from opentine._transcript_corpus import from_files  # noqa: E402
from opentine._transcript_embed import Space  # noqa: E402

TARGET = 0.9


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "corpus", nargs="?", default=str(ROOT / "tests/data/transcript_corpus.jsonl")
    )
    parser.add_argument("--k", type=int, default=50)
    parser.add_argument("--exemplars", type=int, default=5)
    args = parser.parse_args(argv)
    texts, behaviours = from_files([args.corpus])
    space = Space(texts)
    result = recall_at(space, behaviours, k=args.k, exemplars=args.exemplars)
    result["backend"] = space.backend()
    result["corpus_digest"] = space.corpus_digest
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0 if result["min_recall"] >= TARGET else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
