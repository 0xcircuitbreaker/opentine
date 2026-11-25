"""Wire size and speed of TINEPACK6 (HEC) against TINEPACK5 on generated corpora.

Two corpora, both built by the repository's own writers: ``text`` is the
TINEPACK5 bench corpus (``tinepack5.corpus``: many similar recorded runs with
growing histories); ``mixed`` adds random binary blobs (a quarter of the raw
bytes), which HEC cannot see into and the writer sends as plain zstd. Usage::

    uv run python scripts/bench/tinepack6.py [--runs 40] [--steps 30] [--repeat 3]

Prints one JSON object: bytes of TINEPACK5 (wire and slim), each TINEPACK6
candidate and the one kept, and encode/decode throughput in MB/s of canonical
object bytes (best of ``--repeat``). Results: ``docs/bench/0.81-tinepack6.md``.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tinepack5 import corpus  # noqa: E402

from opentine.kernel import ObjectEnvelope  # noqa: E402
from opentine.repository import _pack5, _pack6_build  # noqa: E402
from opentine.repository.pack import inspect_pack  # noqa: E402


def _best(fn, repeat: int):
    best, out = float("inf"), None
    for _ in range(repeat):
        start = time.perf_counter()
        out = fn()
        best = min(best, time.perf_counter() - start)
    return out, best


def _binary(raw: int) -> list[tuple[str, bytes]]:
    rng = random.Random(81)
    out = []
    for _ in range(max(1, raw // 3 // 65536)):
        env = ObjectEnvelope.create("blob", rng.randbytes(65536))
        out.append((env.oid, env.encode()))
    return out


def measure(objects: list[tuple[str, bytes]], repeat: int) -> dict:
    raw = sum(len(data) for _, data in objects)
    mb = raw / 1e6
    v5, v5_s = _best(lambda: _pack5.build(objects, []), repeat)
    slim = _pack5.build(objects, [], slim=True)
    found, _ = _best(lambda: _pack6_build.candidates(objects, []), 1)
    v6, v6_s = _best(lambda: _pack6_build.build(objects, []), repeat)
    _, read5 = _best(lambda: inspect_pack(v5), repeat)
    got, read6 = _best(lambda: inspect_pack(v6), repeat)
    assert got[1] == sorted(objects)
    return {
        "objects": len(objects),
        "raw_bytes": raw,
        "tinepack5": len(v5),
        "tinepack5_slim": len(slim),
        "tinepack6": len(v6),
        "tinepack6_candidates": {name: len(data) for name, data in sorted(found.items())},
        "v5_over_v6": round(len(v5) / len(v6), 2),
        "encode_mb_s": {"tinepack5": round(mb / v5_s, 1), "tinepack6": round(mb / v6_s, 1)},
        "decode_mb_s": {"tinepack5": round(mb / read5, 1), "tinepack6": round(mb / read6, 1)},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=40)
    parser.add_argument("--steps", type=int, default=30)
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        text = corpus(Path(tmp) / "repo", args.runs, args.steps)
    mixed = sorted(text + _binary(sum(len(d) for _, d in text)))
    result = {
        "python": platform.python_version(),
        "machine": platform.machine(),
        "runs": args.runs,
        "steps": args.steps,
        "text": measure(text, args.repeat),
        "mixed": measure(mixed, args.repeat),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
