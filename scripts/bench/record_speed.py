"""Recording throughput bench: steps per second through the record path, as JSON.

Usage::

    uv run python scripts/bench/record_speed.py [--steps 120] [--seed 38] [--out r.json]

Builds one synthetic agent session -- model calls whose request carries the
same system prompt and tool definitions every turn plus a growing message
history, tool calls returning code, and thinking steps -- and records it
through the public writers:

* ``put_run``: the whole session saved at once with ``Repo.put_run``;
* ``recorder``: the session appended event by event with ``Recorder.append``,
  which is what a live hook or proxy capture does.

Throughput is steps per wall-clock second (best of ``--repeat``), single
threaded, in a fresh temporary repository each time. ``--profile`` prints the
top cumulative functions of one recorder pass to stderr. Compare two
checkouts' JSON to see a change.
"""

from __future__ import annotations

import argparse
import cProfile
import json
import platform
import pstats
import random
import sys
import tempfile
import time
from pathlib import Path

from opentine import Run, StepKind, __version__
from opentine.repository import Repo
from opentine.trace.recorder import Recorder
from opentine.trace.schema import TraceEvent

WORDS = "agent tool model file test diff patch error retry schema value query result".split()
SYSTEM = "You are a careful coding agent. " + " ".join(
    f"Rule {n}: read before you edit and keep each change minimal." for n in range(60)
)
TOOLS = [
    {
        "name": name,
        "description": f"{name} " + " ".join(WORDS * 3),
        "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
    }
    for name in ("read_file", "write_file", "bash", "search", "list_dir", "query")
]
TRACE_KIND = {"model": "model", "tool": "tool", "think": "subagent"}


def _text(rng: random.Random, n: int) -> str:
    return " ".join(rng.choice(WORDS) for _ in range(n))


def session(seed: int, steps: int) -> list[tuple[str, dict, dict]]:
    """``(kind, inputs, outputs)`` for each step of one deterministic session."""
    rng = random.Random(seed)
    history: list[dict] = [{"role": "user", "content": _text(rng, 40)}]
    rows: list[tuple[str, dict, dict]] = []
    for index in range(steps):
        if index % 3 == 0:
            reply = _text(rng, rng.randint(20, 80))
            request = {"model": "bench", "system": SYSTEM, "tools": TOOLS}
            rows.append(("model", {**request, "messages": list(history)}, {"text": reply}))
            history.append({"role": "assistant", "content": reply})
        elif index % 3 == 1:
            body = "\n".join(
                f"def f{n}(x):\n    return x + {n}  # {_text(rng, 6)}" for n in range(40)
            )
            rows.append(("tool", {"name": "read_file", "path": f"m{index}.py"}, {"output": body}))
            history.append({"role": "tool", "content": body[:2000]})
        else:
            rows.append(("think", {"text": _text(rng, 30)}, {}))
    return rows


def bench_put_run(rows: list[tuple[str, dict, dict]]) -> float:
    run = Run(id="bench-record", model_info="mock/bench")
    for kind, inputs, outputs in rows:
        run.add_step(StepKind(kind), inputs, outputs)
    with tempfile.TemporaryDirectory() as tmp:
        repo = Repo.init(Path(tmp) / "repo")
        start = time.perf_counter()
        repo.put_run(run, ref="heads/main")
        return time.perf_counter() - start


def bench_recorder(rows: list[tuple[str, dict, dict]]) -> float:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Repo.init(Path(tmp) / "repo")
        recorder = Recorder.start(repo, prompt="bench", system=SYSTEM, capture=False)
        start = time.perf_counter()
        for index, (kind, inputs, outputs) in enumerate(rows):
            event = TraceEvent(
                TRACE_KIND[kind], 1.0 + index, "t", f"s{index}", inputs=inputs, outputs=outputs
            )
            recorder.append(event)
        return time.perf_counter() - start


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--steps", type=int, default=120)
    parser.add_argument("--seed", type=int, default=38)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    rows = session(args.seed, args.steps)
    if args.profile:
        profile = cProfile.Profile()
        profile.runcall(bench_recorder, rows)
        pstats.Stats(profile, stream=sys.stderr).sort_stats("cumulative").print_stats(35)
    report = {"version": __version__, "python": platform.python_version(), "steps": len(rows)}
    for name, bench in (("put_run", bench_put_run), ("recorder", bench_recorder)):
        best = min(bench(rows) for _ in range(args.repeat))
        report[name] = {"seconds": round(best, 4), "steps_per_s": round(len(rows) / best, 2)}
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
