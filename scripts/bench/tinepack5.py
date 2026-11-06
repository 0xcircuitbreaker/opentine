"""Wire size and compress throughput of TINEPACK4 (zstd-9) against TINEPACK5.

The synthetic corpus is many similar runs with growing histories: each run is
recorded step by step, every step's model call carries the whole conversation
so far, and the runs share a system prompt and tool output shapes, as agent
sessions do. Usage::

    uv run python scripts/bench/tinepack5.py [--runs 40] [--steps 30] [--repeat 3]

Prints one JSON object. Throughput is canonical (uncompressed) object bytes
per second of building the pack from its objects, best of ``--repeat``.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from opentine import Recorder, TraceEvent  # noqa: E402
from opentine.repository import Repo, _pack4, _pack5  # noqa: E402
from opentine.repository.pack import inspect_pack  # noqa: E402

SYSTEM = "You are a careful coding agent. Follow the repository conventions. " * 20
FILES = ["src/app.py", "src/db.py", "tests/test_app.py", "README.md", "setup.cfg"]


def _record(repo: Repo, index: int, steps: int, rng: random.Random) -> None:
    ref = f"heads/run-{index:04d}"
    task = f"Fix issue #{1000 + index}: {rng.choice(['crash', 'typo', 'slow query'])}"
    rec = Recorder.start(repo, ref=ref, prompt=task, capture=False)
    history = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": task}]
    for step in range(steps):
        model = step % 2 == 1
        path = rng.choice(FILES)
        body = "".join(
            f"{n:4d}  def handler_{n}(request):  # {path}\n" for n in range(rng.randint(20, 60))
        )
        output = {"text": f"I will now edit {path}. " * 5} if model else {"content": body}
        rec.append(
            TraceEvent(
                kind="model" if model else "tool",
                timestamp=step + 1.0,
                trace_id=f"t{index}",
                span_id=f"s{step}",
                actor="" if model else "read_file",
                inputs={"messages": list(history)} if model else {"path": path},
                outputs=output,
            )
        )
        history.append({"role": "assistant" if model else "tool", "content": json.dumps(output)})
    rec.finalize()


def corpus(path: Path, runs: int, steps: int, seed: int = 37) -> list[tuple[str, bytes]]:
    os.environ["OPENTINE_AUTO_PACK"] = "off"
    repo = Repo.init(path, compression="zlib")
    rng = random.Random(seed)
    for index in range(runs):
        _record(repo, index, steps, rng)
    return sorted((oid, repo.raw(oid)) for oid in repo.iter_oids())


def _measure(build, raw_bytes: int, repeat: int) -> tuple[bytes, float]:
    best, data = float("inf"), b""
    for _ in range(repeat):
        start = time.perf_counter()
        data = build()
        best = min(best, time.perf_counter() - start)
    return data, raw_bytes / best / 1e6


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=40)
    parser.add_argument("--steps", type=int, default=30)
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        objects = corpus(Path(tmp) / "repo", args.runs, args.steps)
    raw = sum(len(data) for _, data in objects)
    v4, v4_mbs = _measure(lambda: _pack4.build(objects, [], "zstd"), raw, args.repeat)
    v5, v5_mbs = _measure(lambda: _pack5.build(objects, []), raw, args.repeat)
    slim, slim_mbs = _measure(lambda: _pack5.build(objects, [], slim=True), raw, args.repeat)
    assert inspect_pack(v4)[1] == inspect_pack(v5)[1] == inspect_pack(slim)[1] == objects
    result = {
        "objects": len(objects),
        "raw_bytes": raw,
        "runs": args.runs,
        "steps": args.steps,
        "tinepack4_zstd9": {"bytes": len(v4), "ratio": round(raw / len(v4), 2), "mb_s": v4_mbs},
        "tinepack5": {"bytes": len(v5), "ratio": round(raw / len(v5), 2), "mb_s": v5_mbs},
        "tinepack5_slim": {
            "bytes": len(slim),
            "ratio": round(raw / len(slim), 2),
            "mb_s": slim_mbs,
        },
        "size_reduction": round(len(v4) / len(v5), 2),
        "throughput_gain": round(v5_mbs / v4_mbs, 2),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
