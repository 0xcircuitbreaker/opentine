"""``tine dataset canary-add|canary-list|canary-check|contamination`` (0.60).

``canary-add TEXT --entropy-bits N --key KEY`` signs a canary registration
(:mod:`opentine._canary`); ``canary-list`` lists registrations without their
text; ``canary-check LENGTHS.json`` refuses a model that codes a counted canary
below its declared entropy (:mod:`opentine._canary_check`); ``contamination
HOLDOUT.jsonl --against CORPUS.jsonl`` reports exact-oid and MinHash 5-gram
near-duplicate leaks (:mod:`opentine._contamination`). Each exits 1 when it
refuses or finds a leak. ``tine integrity scan`` lives in ``_cli_integrity``.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

SCHEMA = "tine-cli-canary/1"
VERBS = ("canary-add", "canary-list", "canary-check", "contamination")


def add_canary_verbs(verbs: Any) -> None:
    add = verbs.add_parser("canary-add", help="Register a canary string with a declared entropy")
    add.add_argument("text", metavar="TEXT", help="The canary (one line, 8..4096 bytes)")
    add.add_argument("--entropy-bits", type=int, required=True, metavar="N")
    add.add_argument("--holdout", metavar="NAME", help="The holdout the canary sits in")
    add.add_argument("--key", required=True, metavar="KEY", help="A dataset-role Ed25519 key")
    add.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    listing = verbs.add_parser("canary-list", help="Registered canaries (never their text)")
    check = verbs.add_parser("canary-check", help="Refuse a model that codes a canary too cheaply")
    check.add_argument("lengths", metavar="LENGTHS.json", help="Per-canary code lengths in bits")
    check.add_argument("--margin-bits", type=int, default=0, metavar="M")
    check.add_argument("--strict", action="store_true", help="Advisory findings block too")
    check.add_argument("--run", metavar="RUN", help="Require the lengths to name this scoring run")
    cont = verbs.add_parser("contamination", help="Exact and near-duplicate holdout leaks")
    cont.add_argument("dataset", metavar="HOLDOUT.jsonl")
    cont.add_argument("--against", action="append", default=[], metavar="CORPUS.jsonl")
    cont.add_argument("--threshold", type=float, default=0.8, help="5-gram Jaccard (default 0.8)")
    for verb in (add, listing, check, cont):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository root")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _row(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _canary

    root = Path(args.repo)
    verb = args.dataset_command
    if verb == "canary-add":
        from opentine._cli_integrity import _key
        from opentine._promote import _now

        row = _canary.register(root, _key(args), args.text, args.entropy_bits, args.holdout,
                               args.at or _now())  # fmt: skip
        return {"ok": True, "canary": _canary.public(row)}
    if verb == "canary-list":
        return {"ok": True, "canaries": [_canary.public(r) for r in _canary.load(root)]}
    if verb == "canary-check":
        from opentine._canary_check import check

        return check(root, Path(args.lengths), margin_bits=args.margin_bits, strict=args.strict,
                     run=args.run)  # fmt: skip
    from opentine import _contamination as cont
    from opentine._eval_dataset import read_jsonl

    if not args.against:
        raise ValueError("contamination needs --against CORPUS.jsonl")
    repo = None
    if (root / ".tine").is_dir():
        from opentine.repo import Repo

        repo = Repo.open(root)
    return cont.check(read_jsonl(Path(args.dataset)), cont.corpus_rows(args.against),
                      threshold=args.threshold, repo=repo)  # fmt: skip


def _say(verb: str, row: dict[str, Any]) -> list[str]:
    if verb == "canary-add":
        c = row["canary"]
        return [
            f"REGISTERED {c['canary_sha256']} ({c['entropy_bits']} bits) counted={c['counted']}"
        ]
    if verb == "canary-list":
        return [f"{c['canary_sha256']} {c['entropy_bits']} bits holdout={c['holdout']} "
                f"counted={c['counted']}" for c in row["canaries"]]  # fmt: skip
    if verb == "canary-check":
        head = "OK" if row["ok"] else "REFUSED"
        return [
            head,
            *(f"  {f['code']} {f['canary_sha256']}: {f['detail']}" for f in row["findings"]),
        ]
    head = "CLEAN" if row["ok"] else "CONTAMINATED"
    return [
        f"{head} {row['counts']}",
        *(f"  exact {e['id']} {e['oid']} in {', '.join(e['found_in'])}" for e in row["exact"]),
        *(f"  near {n['id']} ~ {n['found_in']} jaccard={n['jaccard']}" for n in row["near"]),
    ]


def cmd_canary(args: argparse.Namespace) -> None:
    from opentine._canary import CanaryError
    from opentine._cli_common import _terminal, console
    from opentine._cli_errors import error
    from opentine._cli_json import emit
    from opentine._eval_dataset import DatasetError
    from opentine._key_store import PassphraseUnavailable
    from opentine._signing_keys import SignatureError

    verb = args.dataset_command
    try:
        row = _row(args)
    except (CanaryError, DatasetError, PassphraseUnavailable, SignatureError, OSError,
            ValueError) as exc:  # fmt: skip
        raise error(exc, prefix=f"dataset {verb}: ") from exc
    if args.json:
        emit({"command": f"dataset {verb}", "schema": SCHEMA, **row})
    else:
        for line in _say(verb, row):
            console.print(_terminal(line), markup=False)
    if row.get("ok") is False:
        raise SystemExit(1)


__all__ = ["SCHEMA", "VERBS", "add_canary_verbs", "cmd_canary"]
