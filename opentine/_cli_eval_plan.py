"""``tine eval plan``, ``tine eval reveal`` and the 0.86 ``eval run`` flags.

``eval plan`` signs an ``opentine.eval-plan/1`` (:mod:`opentine._eval_plan`) and
writes the secret its seed commitment opens with (keep it from the optimizer);
``eval reveal`` signs the reveal after the runs. ``eval run --plan`` binds the
run to the plan in ``coverage.json`` and takes its epochs and cluster key;
``--epochs``, ``--cluster-key`` and ``--continue-on-error`` work without one.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

PLAN_SCHEMA = "tine-cli-eval-plan/1"
REVEAL_SCHEMA = "tine-cli-eval-reveal/1"
VERBS = ("plan", "reveal")


def add_run_args(run: Any) -> None:
    run.add_argument("--epochs", type=int, metavar="N",
                     help="Score each item N times; outputs name their epoch")  # fmt: skip
    run.add_argument("--cluster-key", metavar="FIELD", help="Item field that clusters items")
    run.add_argument("--plan", metavar="FILE", help="Run under this signed eval plan")
    run.add_argument("--continue-on-error", action="store_true",
                     help="Record missing outputs and scorer errors; do not abort")  # fmt: skip


def add_verbs(verbs: Any) -> None:
    plan = verbs.add_parser("plan", help="Sign an analysis plan with a committed seed (0.86)")
    plan.add_argument("dataset", metavar="DATASET.jsonl")
    plan.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key that signs")
    plan.add_argument("--out", required=True, metavar="FILE", help="Where the plan goes")
    plan.add_argument("--secret-out", required=True, metavar="FILE",
                      help="Where the seed secret goes (keep it from the optimizer)")  # fmt: skip
    plan.add_argument("--max-candidates", required=True, type=int, metavar="M",
                      help="Candidates this plan may test against one baseline")  # fmt: skip
    plan.add_argument("--metric", choices=("score", "pass_rate"), default="pass_rate")
    plan.add_argument("--reducer", choices=("mean", "pass@k", "pass^k"), default="mean")
    plan.add_argument("--epochs", type=int, default=1, metavar="N", help="Epochs per item")
    plan.add_argument("--test", choices=("paired-bootstrap", "permutation"),
                      default="paired-bootstrap")  # fmt: skip
    plan.add_argument("--alpha", default="0.05", help="Familywise alpha (default 0.05)")
    plan.add_argument("--resamples", type=int, default=2000, help="Resamples (default 2000)")
    plan.add_argument("--correction", choices=("holm", "bonferroni"), default="holm")
    plan.add_argument("--cluster-key", metavar="FIELD", help="Item field that clusters items")
    plan.add_argument("--mde", default="0.05", help="Minimum detectable effect (default 0.05)")
    plan.add_argument("--min-coverage", default="1", help="Scored/planned floor (default 1)")
    reveal = verbs.add_parser("reveal", help="Open a plan's seed commitment after the runs")
    reveal.add_argument("plan", metavar="PLAN")
    reveal.add_argument("--secret", required=True, metavar="FILE", help="The plan's secret")
    reveal.add_argument("--key", required=True, metavar="KEY", help="The plan signer's key")
    reveal.add_argument("--out", required=True, metavar="FILE", help="Where the reveal goes")
    for verb in (plan, reveal):
        verb.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def run_options(args: argparse.Namespace, items: list[dict[str, Any]]) -> dict[str, Any]:
    """``run_eval`` keyword arguments for the 0.86 flags (a ``--plan`` checked here)."""
    from opentine import _eval_plan as plans
    from opentine._eval_dataset import dataset_digest

    epochs, key, sha = args.epochs, args.cluster_key, None
    if args.plan:
        plan = plans.opened_plan(plans.load(Path(args.plan)))
        claim, sha = plan["claim"], plan["sha256"]
        if claim["dataset"] != dataset_digest(items):
            raise ValueError("the plan names another dataset")
        if epochs not in (None, claim["epochs"]) or key not in (None, claim["cluster_key"]):
            raise ValueError("--epochs and --cluster-key must match the plan")
        epochs, key = claim["epochs"], claim["cluster_key"]
    epochs = 1 if epochs is None else epochs
    if not 1 <= epochs <= 100:
        raise ValueError("--epochs must be in 1..100")
    return {"epochs": epochs, "cluster_key": key, "plan_sha256": sha,
            "lenient": args.continue_on_error}  # fmt: skip


def _write_secret(path: Path, secret: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write((secret + "\n").encode("ascii"))


def run_verb(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _eval_plan as plans
    from opentine._eval_dataset import dataset_digest, read_jsonl
    from opentine._signing_keys import ed25519_private_from_file
    from opentine._utc import rfc3339_utc

    key = ed25519_private_from_file(args.key, signer=False)
    at = args.at or rfc3339_utc()
    if args.eval_command == "reveal":
        plan = plans.load(Path(args.plan))
        secret = Path(args.secret).read_bytes().decode("ascii").strip()
        doc = plans.make_reveal(key, plan, secret, at)
        plans.dump(Path(args.out), doc)
        sha = plans.file_sha256(plan)
        return {"schema": REVEAL_SCHEMA, "ok": True, "plan_sha256": sha,
                "seed": plans.derive_seed(secret, sha),
                "path": Path(args.out).as_posix()}  # fmt: skip
    if Path(args.secret_out).exists():
        raise ValueError(f"--secret-out {args.secret_out} exists: a secret is never overwritten")
    fields = {"dataset": dataset_digest(read_jsonl(Path(args.dataset))), "metric": args.metric,
              "reducer": args.reducer, "epochs": args.epochs, "test": args.test,
              "alpha": args.alpha, "resamples": args.resamples, "correction": args.correction,
              "max_candidates": args.max_candidates, "cluster_key": args.cluster_key,
              "mde": args.mde, "min_coverage": args.min_coverage}  # fmt: skip
    secret = plans.new_secret()
    doc = plans.make_plan(key, fields, secret, at)
    _write_secret(Path(args.secret_out), secret)
    plans.dump(Path(args.out), doc)
    return {"schema": PLAN_SCHEMA, "ok": True, "plan": doc["claim"], "signer": doc["signer"],
            "plan_sha256": plans.file_sha256(doc), "path": Path(args.out).as_posix(),
            "secret_path": Path(args.secret_out).as_posix()}  # fmt: skip


def human(row: dict[str, Any]) -> None:
    from opentine._cli_common import console

    if row["schema"] == PLAN_SCHEMA:
        plan = row["plan"]
        text = (f"PLAN {row['plan_sha256']}: {plan['metric']} {plan['reducer']} x{plan['epochs']}, "
                f"{plan['test']} alpha {plan['alpha']} ({plan['correction']}, "
                f"m<={plan['max_candidates']}); secret in {row['secret_path']}")  # fmt: skip
    else:
        text = f"REVEALED {row['plan_sha256']}: seed {row['seed']}"
    console.print(text, highlight=False, markup=False)


__all__ = ["PLAN_SCHEMA", "REVEAL_SCHEMA", "VERBS", "add_run_args", "add_verbs", "human",
           "run_options", "run_verb"]  # fmt: skip
