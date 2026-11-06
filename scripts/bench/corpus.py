"""Deterministic synthetic agent-run corpus for the compression bench.

The shape is what agent recordings look like in practice: many similar runs
that share a handful of system prompts, message histories that grow by one
turn per step (so consecutive model inputs are near-duplicates), tool outputs
that are source code or JSON, and a few large blobs that change by a small
edit between runs. Everything is derived from ``random.Random(seed)`` so the
same ``(seed, runs, steps)`` always yields identical runs.
"""

from __future__ import annotations

import json
import random
from collections.abc import Iterator
from dataclasses import replace

from opentine import Run, RunStatus, StepKind

WORDS = (
    "agent tool model request response cache token budget plan step file test "
    "repository commit branch merge diff patch error retry timeout schema field "
    "value index query result summary context window stream chunk parse render"
).split()

SYSTEM_PROMPTS = [
    "You are a careful coding agent. Read files before editing them. "
    + " ".join(f"Rule {n}: keep changes minimal and explain each one." for n in range(40)),
    "You are a research assistant. Cite every source you rely on. "
    + " ".join(f"Guideline {n}: prefer primary sources over summaries." for n in range(35)),
    "You are a data analyst. Show the query before the answer. "
    + " ".join(f"Policy {n}: never invent a number you did not compute." for n in range(30)),
]

BIG_BLOB_BYTES = 256 * 1024
EPOCH = 1_767_225_600.0  # 2026-01-01T00:00:00Z


def _sentence(rng: random.Random, n: int) -> str:
    return " ".join(rng.choice(WORDS) for _ in range(n)).capitalize() + "."


def _code(rng: random.Random, funcs: int) -> str:
    out = ["from __future__ import annotations", "", "import json", ""]
    for i in range(funcs):
        name = f"{rng.choice(WORDS)}_{rng.choice(WORDS)}_{i}"
        arg = rng.choice(WORDS)
        out += [
            f"def {name}({arg}: dict) -> int:",
            f'    """{_sentence(rng, 8)}"""',
            f"    total = len({arg})",
            f"    for key, value in sorted({arg}.items()):",
            f"        if value is None:  # {rng.choice(WORDS)}",
            f"            total -= {rng.randint(1, 9)}",
            "        total += len(json.dumps(value))",
            "    return total",
            "",
        ]
    return "\n".join(out)


def _json_rows(rng: random.Random, rows: int) -> str:
    data = [
        {
            "id": rng.randint(1, 10**6),
            "name": f"{rng.choice(WORDS)}-{rng.choice(WORDS)}",
            "score": round(rng.random(), 4),
            "tags": rng.sample(WORDS, 3),
            "ok": rng.random() > 0.2,
        }
        for _ in range(rows)
    ]
    return json.dumps({"rows": data, "count": rows}, indent=2)


def _base_blob(seed: int) -> list[str]:
    rng = random.Random(seed ^ 0xB10B)
    lines: list[str] = []
    size = 0
    while size < BIG_BLOB_BYTES:
        lines.append(f"{len(lines):06d} {_sentence(rng, 10)}")
        size += len(lines[-1]) + 1
    return lines


def generate(seed: int = 37, runs: int = 40, steps: int = 24) -> Iterator[Run]:
    """Yield *runs* deterministic runs of *steps* steps (plus a final ``done``)."""
    rng = random.Random(seed)
    big = [_base_blob(seed + n) for n in range(2)]
    for r in range(runs):
        run = Run(
            id=f"bench-{seed}-{r:04d}",
            run_id=f"bench-{seed}-{r:04d}",
            created_at=EPOCH + r * 3600,
            model_info="mock/bench-model",
        )
        history: list[dict] = [
            {"role": "system", "content": SYSTEM_PROMPTS[r % len(SYSTEM_PROMPTS)]},
            {"role": "user", "content": _sentence(rng, 30)},
        ]
        for s in range(steps):
            if s % 3 == 0:  # model call: the whole growing history is its input
                reply = _sentence(rng, rng.randint(20, 80))
                history.append({"role": "assistant", "content": reply})
                run.add_step(
                    StepKind.model,
                    {"messages": list(history)},
                    {"text": reply},
                    usage={"input": 50 * len(history), "output": 40},
                )
            elif s % 3 == 1:  # tool call: code, JSON, or a large blob with a small edit
                pick = rng.random()
                if pick < 0.45:
                    output = _code(rng, rng.randint(3, 12))
                elif pick < 0.9:
                    output = _json_rows(rng, rng.randint(5, 40))
                else:
                    lines = big[r % 2]
                    at = rng.randrange(len(lines))
                    lines[at] = f"{at:06d} edited in run {r} step {s}: {_sentence(rng, 6)}"
                    output = "\n".join(lines)
                history.append({"role": "tool", "content": output[:4000]})
                run.add_step(
                    StepKind.tool,
                    {"name": rng.choice(("read_file", "query", "search")), "arg": r},
                    {"output": output},
                )
            else:
                run.add_step(StepKind.think, {"text": _sentence(rng, rng.randint(10, 40))})
        run.add_step(StepKind.done, {"text": f"run {r} finished"})
        for n, step in enumerate(run.steps):  # wall-clock stamps would vary per build
            run.graph.steps[step.id] = replace(step, timestamp=EPOCH + r * 3600 + n * 1.5)
        run.status = RunStatus.completed
        yield run
