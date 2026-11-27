"""Shared fixtures for the 0.86 eval-plan and promotion-discipline tests (deterministic)."""

from __future__ import annotations

import json
from pathlib import Path

from opentine import _eval_plan as plans
from opentine._eval_dataset import dataset_digest
from opentine._eval_run import run_eval
from opentine._eval_scorers import parse
from tests.promote_helpers import AT, EVALER, key

BEFORE = "2026-11-01T11:00:00Z"
AFTER = "2026-11-01T13:00:00Z"
SECRET = "5e" * 32


def items(n: int = 40, dataset: str = "main", families: int = 0) -> list[dict]:
    rows = [{"id": f"{dataset}-{i:03d}", "input": f"{dataset} {i}", "expected": "yes"}
            for i in range(n)]  # fmt: skip
    for i, row in enumerate(rows):
        if families:
            row["metadata"] = {"family": f"f{i % families}"}
    return rows


def plan_fields(rows: list[dict], **over) -> dict:
    return {"dataset": dataset_digest(rows), "metric": "pass_rate", "reducer": "mean",
            "epochs": 1, "test": "paired-bootstrap", "alpha": "0.05", "resamples": 500,
            "correction": "holm", "max_candidates": 1, "cluster_key": None, "mde": "0.1",
            "min_coverage": "1", **over}  # fmt: skip


def write_plan(base: Path, rows: list[dict], *, signer: str = EVALER, at: str = BEFORE,
               secret: str = SECRET, name: str = "plan.json",
               **over) -> tuple[Path, Path]:  # fmt: skip
    """A signed plan and its reveal (signed after the runs)."""
    doc = plans.make_plan(key(signer), plan_fields(rows, **over), secret, at)
    plan = base / name
    plans.dump(plan, doc)
    reveal = base / f"reveal-{name}"
    plans.dump(reveal, plans.make_reveal(key(signer), doc, secret, AFTER))
    return plan, reveal


def plan_sha(path: Path) -> str:
    return plans.file_sha256(json.loads(path.read_bytes()))


def run(out: Path, rows: list[dict], run_id: str, passing, *, epochs: int = 1,
        plan: Path | None = None, signer: str = EVALER, at: str = AT, missing=(),
        cluster_key: str | None = None) -> Path:  # fmt: skip
    """An exact-scored eval; epoch e of item i passes when ``passing(i, e)``."""
    outputs = {}
    for row in rows:
        i = int(row["id"].rsplit("-", 1)[1])
        for e in range(epochs):
            vid = row["id"] if epochs == 1 else f"{row['id']}@e{e}"
            if vid not in missing:
                outputs[vid] = {"output": "yes" if passing(i, e) else "no", "run": run_id}
    run_eval(rows, parse("exact"), key(signer), out, outputs=outputs, created_at=at,
             epochs=epochs, lenient=bool(missing), cluster_key=cluster_key,
             plan_sha256=plan_sha(plan) if plan else None)  # fmt: skip
    return out
