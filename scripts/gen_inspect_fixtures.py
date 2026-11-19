"""Write the committed Inspect log fixtures (0.64): small, synthetic, offline.

    python scripts/gen_inspect_fixtures.py

Five logs shaped like what Inspect writes for five inspect_evals tasks (the task
names and the inspect_evals commit are pinned in ``MANIFEST.json``). Questions,
answers and model output are synthetic placeholders, not dataset content, and
nothing is downloaded. Two logs are ``.eval`` zips (fixed member timestamps, so
the bytes are reproducible); three are ``.json``.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests" / "fixtures" / "inspect"
INSPECT_EVALS = "https://github.com/UKGovernmentBEIS/inspect_evals"
INSPECT_EVALS_COMMIT = "c2d3d5e1335c07fb8032bcfc7869e9437e635c4c"
MODEL = "mockllm/model"

# task, file, sample ids, epochs, scorer, sandbox, extra score kinds
TASKS = (
    ("gsm8k", "gsm8k.json", [1, 2, 3], 1, "match", None),
    ("arc_easy", "arc_easy.eval", ["Mercury_7175875", "Mercury_SC_409171", "MCAS_2000_4_6"],
     1, "choice", None),
    ("humaneval", "humaneval.eval", ["HumanEval/0", "HumanEval/1", "HumanEval/2"], 1, "verify",
     {"type": "docker", "config": None}),
    ("gpqa_diamond", "gpqa_diamond.json", ["rec06pnAkLOr2t2mp", "rec0Arme2jcXQZnAW"], 2,
     "choice", None),
    ("boolq", "boolq.json", [0, 1, 2], 1, "pattern", None),
)  # fmt: skip


def _sample(task: str, ident, epoch: int, scorer: str, n: int) -> dict:
    correct = (n + epoch) % 3 != 0
    answer = "A" if correct else "B"
    messages = [
        {"id": f"m{n}-0", "role": "system", "content": "Answer the question.", "source": "input"},
        {"id": f"m{n}-1", "role": "user", "content": f"Synthetic question {n} for {task}.",
         "source": "input"},
    ]  # fmt: skip
    if task == "humaneval":
        messages.append({"id": f"m{n}-2", "role": "assistant", "content": "",
                         "tool_calls": [{"id": f"call{n}", "function": "python",
                                         "arguments": {"code": "print(1)"}}],
                         "model": MODEL, "source": "generate"})  # fmt: skip
        messages.append({"id": f"m{n}-3", "role": "tool", "content": "1\n",
                         "tool_call_id": f"call{n}", "function": "python"})  # fmt: skip
    messages.append({"id": f"m{n}-9", "role": "assistant", "content": f"ANSWER: {answer}",
                     "model": MODEL, "source": "generate"})  # fmt: skip
    scores = {scorer: {"value": "C" if correct else "I", "answer": answer,
                       "explanation": f"ANSWER: {answer}", "metadata": {}}}  # fmt: skip
    if task == "boolq":  # a numeric score and one with no 0..1 reading
        scores["confidence"] = {"value": round(0.25 * (n + 1), 2)}
        scores["breakdown"] = {"value": {"exact": 1, "partial": 0.5}}
    return {
        "id": ident, "epoch": epoch, "input": f"Synthetic question {n} for {task}.",
        "target": "A", "messages": messages,
        "output": {"model": MODEL, "choices": [{"message": messages[-1], "stop_reason": "stop"}],
                   "completion": f"ANSWER: {answer}"},
        "scores": scores, "metadata": {"synthetic": True},
    }  # fmt: skip


def build(task, ids, epochs, scorer, sandbox) -> dict:
    samples = [_sample(task, ident, e, scorer, n)
               for e in range(1, epochs + 1) for n, ident in enumerate(ids)]  # fmt: skip
    head = {
        "eval_id": f"fixture-{task}", "run_id": f"fixture-run-{task}",
        "created": "2026-11-01T12:00:00+00:00", "task": f"inspect_evals/{task}",
        "task_id": f"fixture-task-{task}", "task_version": 0, "model": MODEL,
        "dataset": {"name": task, "samples": len(ids), "sample_ids": ids},
        "task_args": {}, "config": {"epochs": epochs},
        "packages": {"inspect_ai": "0.3.140", "inspect_evals": INSPECT_EVALS_COMMIT[:12]},
    }  # fmt: skip
    if sandbox:
        head["sandbox"] = sandbox
    passed = sum(1 for s in samples if s["scores"][scorer]["value"] == "C")
    results = {"total_samples": len(samples), "completed_samples": len(samples),
               "scores": [{"name": scorer, "scorer": scorer, "metrics": {
                   "accuracy": {"name": "accuracy", "value": passed / len(samples)}}}]}  # fmt: skip
    return {"version": 2, "status": "success", "eval": head, "results": results,
            "samples": samples}  # fmt: skip


def eval_zip(log: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:

        def put(name: str, value) -> None:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, json.dumps(value, indent=2).encode())

        put("_journal/start.json", {k: log[k] for k in ("version", "eval")})
        put("header.json", {k: v for k, v in log.items() if k != "samples"})
        for sample in log["samples"]:
            put(f"samples/{sample['id']}_epoch_{sample['epoch']}.json", sample)
    return buffer.getvalue()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for task, name, ids, epochs, scorer, sandbox in TASKS:
        log = build(task, ids, epochs, scorer, sandbox)
        data = (
            eval_zip(log) if name.endswith(".eval") else (json.dumps(log, indent=2) + "\n").encode()
        )
        (OUT / name).write_bytes(data)
        rows.append({"task": f"inspect_evals/{task}", "file": name, "samples": len(log["samples"]),
                     "scorers": sorted(log["samples"][0]["scores"])})  # fmt: skip
    manifest = {"inspect_evals": INSPECT_EVALS, "inspect_evals_commit": INSPECT_EVALS_COMMIT,
                "content": "synthetic; shapes follow the Inspect EvalLog format (version 2)",
                "generator": "scripts/gen_inspect_fixtures.py", "fixtures": rows}  # fmt: skip
    (OUT / "MANIFEST.json").write_bytes((json.dumps(manifest, indent=2) + "\n").encode())


if __name__ == "__main__":
    main()
