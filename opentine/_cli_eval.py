"""``tine eval run|verify|compare|ci``: signed tine-eval-verdict/1 evals (0.45, 0.47)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from opentine._cli_dataset import COMMANDS as DATASET_COMMANDS
from opentine._cli_dataset import add_dataset_parser
from opentine._cli_errors import ERROR, VERIFICATION_FAILED, fail


def add_eval_parsers(sub: Any) -> None:
    evals = sub.add_parser("eval", help="Score a dataset into signed verdicts; verify, compare")
    verbs = evals.add_subparsers(dest="eval_command", required=True)
    run = verbs.add_parser("run", help="Score every dataset item and sign one verdict each")
    run.add_argument("dataset", metavar="DATASET.jsonl")
    run.add_argument("--scorer", required=True, metavar="SPEC",
                     help="exact | regex:PAT | json-schema:FILE | python:MOD:FUNC | "
                          "llm-judge:PROVIDER[:MODEL]")  # fmt: skip
    run.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key that signs")
    run.add_argument("--out", required=True, metavar="DIR", help="Eval folder to write")
    run.add_argument("--threshold", type=float, default=1.0, help="Pass mark in 0..1 (default 1)")
    run.add_argument("--outputs", metavar="FILE.jsonl", help="{id, output, run} lines to score")
    run.add_argument("--run", dest="default_run", metavar="RUN", help="Run for items naming none")
    run.add_argument("--judge-prompt", metavar="FILE", help="llm-judge prompt template")
    run.add_argument("--created-at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    verify = verbs.add_parser("verify", help="Verify an eval folder's verdicts offline")
    verify.add_argument("eval_dir", metavar="DIR")
    compare = verbs.add_parser("compare", help="Diff two evals item by item (both verified)")
    compare.add_argument("left", metavar="A")
    compare.add_argument("right", metavar="B")
    compare.add_argument("--exit-code", action="store_true", help="Exit 1 on any regression")
    ci = verbs.add_parser("ci", help="Run every eval .tine/evals.toml declares; gate on them")
    ci.add_argument("--config", metavar="TOML", help="Eval config (default: .tine/evals.toml)")
    ci.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key that signs")
    ci.add_argument("--out", metavar="DIR", help="Where eval folders go (default .tine/evals)")
    ci.add_argument("--repo", default=".", help="The directory holding .tine/")
    ci.add_argument("--created-at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    for verb in (verify, compare):
        verb.add_argument("--pubkey", metavar="PUB", help="Trusted Ed25519 public key")
    for verb in (run, verify, compare, ci):
        verb.add_argument("--json", action="store_true", help="Print a JSON object")
    add_dataset_parser(sub)


def _pubkey(args: argparse.Namespace) -> bytes | None:
    from opentine._signing_keys import ed25519_public_from_file

    return ed25519_public_from_file(args.pubkey).public_bytes_raw() if args.pubkey else None


def _outputs(path: str | None) -> dict[str, dict[str, Any]] | None:
    if not path:
        return None
    rows = [json.loads(line) for line in Path(path).read_text("utf-8").splitlines() if line.strip()]
    return {str(row["id"]): row for row in rows}


def _run(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._eval_dataset import read_jsonl
    from opentine._eval_run import run_eval
    from opentine._eval_scorers import parse
    from opentine._signing_keys import ed25519_private_from_file

    prompt = Path(args.judge_prompt).read_text("utf-8") if args.judge_prompt else None
    scorer = parse(args.scorer, prompt=prompt) if args.scorer.startswith("llm-judge:") else (
        parse(args.scorer)
    )  # fmt: skip
    key = ed25519_private_from_file(args.key, signer=False)
    return run_eval(read_jsonl(Path(args.dataset)), scorer, key, Path(args.out),
                    threshold=args.threshold, outputs=_outputs(args.outputs),
                    default_run=args.default_run, created_at=args.created_at)  # fmt: skip


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
    try:
        if verb == "run":
            row = {"ok": True, **_run(args)}
        elif verb == "ci":
            row = _ci(args)
        elif verb == "verify":
            row = verify_eval(Path(args.eval_dir), public_key=_pubkey(args))
        else:
            row = compare(Path(args.left), Path(args.right), public_key=_pubkey(args))
    except errors as exc:
        fail(exc, ERROR, prefix=f"eval {verb}: ", cause=exc)
    if args.json:
        emit({"command": f"eval {verb}", **row})
    else:
        _human(verb, row)
    if verb == "ci" and not row["ok"]:
        raise SystemExit(1)
    failed = not row["ok"] or (verb == "compare" and args.exit_code and row["regressed"])
    if failed:
        raise SystemExit(VERIFICATION_FAILED if not row["ok"] else 1)


COMMANDS = {"eval": cmd_eval, **DATASET_COMMANDS}

__all__ = ["COMMANDS", "add_eval_parsers", "cmd_eval"]
