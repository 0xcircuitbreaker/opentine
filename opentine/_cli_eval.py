"""``tine eval run|verify|compare|ci``: signed tine-eval-verdict/1 evals (0.45, 0.47, 0.58)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from opentine._cli_dataset import COMMANDS as DATASET_COMMANDS
from opentine._cli_dataset import add_dataset_parser
from opentine._cli_errors import ERROR, VERIFICATION_FAILED, fail
from opentine._cli_label import COMMANDS as LABEL_COMMANDS
from opentine._cli_label import add_label_parser


def add_eval_parsers(sub: Any) -> None:
    evals = sub.add_parser("eval", help="Score a dataset into signed verdicts; verify, compare")
    verbs = evals.add_subparsers(dest="eval_command", required=True)
    run = verbs.add_parser("run", help="Score every dataset item and sign one verdict each")
    run.add_argument("dataset", metavar="DATASET.jsonl")
    run.add_argument("--scorer", required=True, metavar="SPEC",
                     help="exact | regex:PAT | json-schema:FILE | python:MOD:FUNC | "
                          "llm-judge:PROVIDER[:MODEL] | plugin:NAME")  # fmt: skip
    run.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key that signs")
    run.add_argument("--out", required=True, metavar="DIR", help="Eval folder to write")
    run.add_argument("--threshold", type=float, default=1.0, help="Pass mark in 0..1 (default 1)")
    run.add_argument("--outputs", metavar="FILE.jsonl", help="{id, output, run} lines to score")
    run.add_argument("--run", dest="default_run", metavar="RUN", help="Run for items naming none")
    run.add_argument("--judge-prompt", metavar="FILE", help="llm-judge prompt template")
    run.add_argument("--judge-rubric", metavar="FILE", help="llm-judge rubric (0.65)")
    run.add_argument("--created-at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    run.add_argument(
        "--holdout",
        metavar="DIR",
        help="Sealed holdout DATASET came from: refuse runs that touched it",
    )
    run.add_argument("--repo", default=".", help="Repository holding the scored runs")
    run.add_argument("--lineage", metavar="NODE", help="Lineage node a holdout query counts for")
    from opentine._cli_eval_scorer import add_run_args, add_verbs

    add_run_args(run)  # 0.85: --isolate, --contract, closure pins
    from opentine import _cli_eval_plan as planning

    planning.add_run_args(run)  # 0.86: --epochs, --cluster-key, --plan, --continue-on-error
    verify = verbs.add_parser("verify", help="Verify an eval folder's verdicts offline")
    verify.add_argument("eval_dir", metavar="DIR")
    compare = verbs.add_parser("compare", help="Diff two evals item by item (both verified)")
    compare.add_argument("left", metavar="A")
    compare.add_argument("right", metavar="B")
    compare.add_argument("--exit-code", action="store_true", help="Exit 1 on any regression")
    compare.add_argument(
        "--ci",
        choices=("paired-bootstrap", "permutation"),
        help="Per-metric deltas with an interval or p-value (0.58)",
    )
    compare.add_argument("--alpha", default="0.05", help="Significance level (default 0.05)")
    compare.add_argument("--seed", type=int, default=0, help="Resampling seed (default 0)")
    compare.add_argument("--resamples", type=int, default=2000, help="Resamples (default 2000)")
    compare.add_argument("--export", metavar="FILE", help="Write the export --ci computed from")
    compare.add_argument("--attest", metavar="KEY", help="Sign the result as an attestation")
    compare.add_argument("--out", metavar="FILE", help="Where --attest writes it")
    compare.add_argument("--signed-at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default now)")
    ci = verbs.add_parser("ci", help="Run every eval .tine/evals.toml declares; gate on them")
    ci.add_argument("--config", metavar="TOML", help="Eval config (default: .tine/evals.toml)")
    ci.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key that signs")
    ci.add_argument("--out", metavar="DIR", help="Where eval folders go (default .tine/evals)")
    ci.add_argument("--repo", default=".", help="The directory holding .tine/")
    ci.add_argument("--created-at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    add_verbs(verbs)  # 0.85: rescore, lint
    planning.add_verbs(verbs)  # 0.86: plan, reveal
    for verb in (verify, compare):
        verb.add_argument("--pubkey", metavar="PUB", help="Trusted Ed25519 public key")
    for verb in (run, verify, compare, ci):
        verb.add_argument("--json", action="store_true", help="Print a JSON object")
    add_dataset_parser(sub)
    add_label_parser(sub)  # 0.89: tine label (rubric label queues)


def _pubkey(args: argparse.Namespace) -> bytes | None:
    from opentine._signing_keys import ed25519_public_from_file

    return ed25519_public_from_file(args.pubkey).public_bytes_raw() if args.pubkey else None


def _outputs(path: str | None) -> dict[str, dict[str, Any]] | None:
    if not path:
        return None
    from opentine._eval_coverage import keyed_outputs

    rows = [json.loads(line) for line in Path(path).read_text("utf-8").splitlines() if line.strip()]
    return keyed_outputs(rows)  # 0.86: an "epoch" names ID@eK


def _run(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._eval_dataset import read_jsonl
    from opentine._eval_run import run_eval
    from opentine._eval_scorers import parse
    from opentine._holdout_query import LINEAGE_RE
    from opentine._signing_keys import ed25519_private_from_file

    if args.lineage is not None and not LINEAGE_RE.fullmatch(args.lineage):
        raise ValueError(f"--lineage must match {LINEAGE_RE.pattern}")  # before anything is signed
    prompt = Path(args.judge_prompt).read_text("utf-8") if args.judge_prompt else None
    rubric = Path(args.judge_rubric).read_bytes().decode("utf-8") if args.judge_rubric else None
    from opentine._cli_eval_scorer import build

    scorer, advisories = build(args, lambda: (
        parse(args.scorer, prompt=prompt, rubric=rubric)
        if args.scorer.startswith("llm-judge:") else parse(args.scorer)))  # fmt: skip
    key = ed25519_private_from_file(args.key, signer=False)
    if args.holdout:
        from opentine._eval_holdout import refuse_touched

        refuse_touched(args, read_jsonl(Path(args.dataset)), _outputs(args.outputs))
    from opentine._cli_eval_plan import run_options

    items = read_jsonl(Path(args.dataset))
    summary = run_eval(items, scorer, key, Path(args.out),
                       threshold=args.threshold, outputs=_outputs(args.outputs),
                       default_run=args.default_run, created_at=args.created_at,
                       **run_options(args, items))  # fmt: skip
    found = scorer.config.get("closure")
    if found is not None:
        from opentine._scorer_closure import closure_digest

        summary["closure"] = closure_digest(found)
        summary["isolation"] = found["isolation"]["level"]
    from opentine._eval_holdout import record_queries

    summary["holdout_queries"] = record_queries(args, key, summary)  # 0.86
    return {**summary, "advisories": advisories}


def _ci(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._eval_ci import CONFIG, run_ci
    from opentine._signing_keys import ed25519_private_from_file

    base = Path(args.repo)
    config = Path(args.config) if args.config else base / CONFIG
    out = Path(args.out or ".tine/evals")
    out = out if out.is_absolute() else base / out
    key = ed25519_private_from_file(args.key, signer=False)
    return run_ci(config, key, out, repo_path=base, created_at=args.created_at)


def _human(verb: str, row: dict[str, Any]) -> None:
    from opentine._cli_common import console

    for item in row.get("refusals", []):
        console.print(f"REFUSED {item['code']}: {item['detail']}", highlight=False, markup=False)
    if "refusals" in row:
        return
    for item in row.get("advisories", []):
        console.print(f"ADVISORY {item['code']}: {item['detail']}", highlight=False, markup=False)

    if verb in ("rescore", "lint", "plan", "reveal"):
        from opentine import _cli_eval_plan, _cli_eval_scorer

        (_cli_eval_plan if verb in _cli_eval_plan.VERBS else _cli_eval_scorer).human(row)
        return
    if verb == "ci":
        for item in row["evals"]:
            head = "PASS" if item["ok"] else "FAIL"
            text = f"{head} {item['name']}: {item['passed']}/{item['items']} passed"
            console.print(f"{text} (needs {item['min_pass_rate']})", highlight=False, markup=False)
        return

    if verb == "compare":
        console.print(
            f"mean delta {row['mean_delta']}  regressed {len(row['regressed'])}  "
            f"fixed {len(row['fixed'])}  changed {len(row['changed'])}  "
            f"only A {len(row['only_a'])}  only B {len(row['only_b'])}",
            highlight=False, markup=False,
        )  # fmt: skip
        for item in row["regressed"]:
            console.print(f"  regressed  {item}", highlight=False, markup=False)
        if row.get("stats"):
            from opentine._cli_eval_compare import table

            table(row)
        return
    head = "VERIFIED" if row.get("ok", True) else "FAILED"
    console.print(
        f"{head} {row.get('eval')}: {row['items']} item(s), {row['passed']} passed, "
        f"mean score {row['mean_score']}",
        highlight=False, markup=False,
    )  # fmt: skip
    for failure in row.get("failures", [])[:20]:
        console.print(f"  line {failure['line']}: {failure['reason']}", markup=False)


def cmd_eval(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine._eval_dataset import DatasetError
    from opentine._eval_run import compare, verify_eval
    from opentine._eval_scorers import ScorerError
    from opentine._eval_verdict import EvalVerdictError
    from opentine._key_store import PassphraseUnavailable
    from opentine._signing_keys import SignatureError

    verb = args.eval_command
    errors = (DatasetError, ScorerError, EvalVerdictError, PassphraseUnavailable, SignatureError,
              OSError, ValueError, KeyError, ImportError)  # fmt: skip
    from opentine._eval_holdout import HoldoutTouched
    from opentine._scorer_isolated import ScorerRefused

    try:
        if verb == "run":
            row = {"ok": True, **_run(args)}
        elif verb in ("rescore", "lint", "plan", "reveal"):
            from opentine import _cli_eval_plan, _cli_eval_scorer

            source = _cli_eval_plan if verb in _cli_eval_plan.VERBS else _cli_eval_scorer
            row = source.run_verb(args)
        elif verb == "ci":
            row = _ci(args)
        elif verb == "verify":
            row = verify_eval(Path(args.eval_dir), public_key=_pubkey(args))
        elif args.ci:
            from opentine._cli_eval_compare import compare_ci

            row = compare_ci(args, _pubkey(args))
        else:
            row = compare(Path(args.left), Path(args.right), public_key=_pubkey(args))
    except HoldoutTouched as exc:
        row = {"ok": False, "refusals": exc.refusals}
    except ScorerRefused as exc:  # 0.85: isolation breach, closure mismatch, contract
        row = {"ok": False, "refusals": exc.refusals()}
    except errors as exc:
        fail(exc, ERROR, prefix=f"eval {verb}: ", cause=exc)
    if args.json:
        emit({"command": f"eval {verb}", **row})
    else:
        _human(verb, row)
    if "refusals" in row:  # 0.60 eval.holdout-touched: refused, nothing signed
        raise SystemExit(1)
    if verb == "ci" and not row["ok"]:
        raise SystemExit(1)
    regressed = row.get("regressed") or (row.get("stats") or {}).get("regressions")
    failed = not row["ok"] or (verb == "compare" and args.exit_code and regressed)
    if failed:
        raise SystemExit(VERIFICATION_FAILED if not row["ok"] else 1)


COMMANDS = {"eval": cmd_eval, **DATASET_COMMANDS, **LABEL_COMMANDS}

__all__ = ["COMMANDS", "add_eval_parsers", "cmd_eval"]
