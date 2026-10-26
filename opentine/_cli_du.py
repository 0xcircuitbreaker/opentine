"""``tine du`` (repository footprint) and ``tine prune`` (dry run unless ``--delete``)."""

from __future__ import annotations

import argparse
import json

from opentine._cli_common import BRAND, _terminal, console


def _size(count: int) -> str:
    from opentine._cli_storage import _size as size

    return size(count)


def add_du_parsers(sub: argparse._SubParsersAction) -> None:
    du = sub.add_parser("du", help="Show repository disk usage by kind, run or ref")
    du.add_argument("--repo", default=".")
    du.add_argument("--by", choices=("kind", "run", "ref"), default="kind")
    du.add_argument("--json", action="store_true")
    prune = sub.add_parser(
        "prune", help="List unreachable old objects; delete them only with --delete"
    )
    prune.add_argument("--repo", default=".")
    prune.add_argument(
        "--delete", action="store_true", help="Actually delete (default: dry run, nothing removed)"
    )
    prune.add_argument(
        "--older-than",
        type=float,
        default=14.0,
        metavar="DAYS",
        help="Only objects last written this many days ago (default 14; floor 60 s)",
    )
    prune.add_argument(
        "--no-git-links",
        action="store_true",
        help="Do not treat runs named by the git checkout's trailers/notes as roots",
    )
    prune.add_argument(
        "--reflog-expire",
        type=float,
        metavar="DAYS",
        help="Expire reflog rows older than DAYS first (default: the repository policy)",
    )
    prune.add_argument("--json", action="store_true")


def _repo(path: str):
    from opentine.repository import Repo

    return Repo.open(path)


def _refuse(exc: Exception) -> None:
    console.print(f"[red]{_terminal(exc)}[/]")
    raise SystemExit(1) from exc


def cmd_du(args: argparse.Namespace) -> None:
    from opentine.repository._du import usage

    try:
        report = usage(_repo(args.repo), args.by)
    except (OSError, ValueError) as exc:
        _refuse(exc)
    if args.json:
        print(json.dumps(report, sort_keys=True))
        return
    loose, packed = report["loose"], report["packed"]
    console.print(f"[{BRAND}]# Repository[/] {_size(report['total_bytes'])}")
    console.print(
        f"  loose   {loose['objects']} object(s), {_size(loose['stored_bytes'])} "
        f"({loose['fanout_dirs']} fan-out dir(s), {loose['empty_fanout_dirs']} empty)"
    )
    console.print(
        f"  packed  {packed['objects']} object(s), {_size(packed['file_bytes'])} "
        f"in {packed['files']} file(s)"
    )
    for name in ("refs", "logs", "indexes"):
        console.print(f"  {name:<7} {_size(report[name]['bytes'])}")
    section = report[f"by_{args.by}"]
    rows = (
        section.items() if args.by == "kind" else [(r.get("ref") or r["run"], r) for r in section]
    )
    for label, row in rows:
        console.print(
            f"  {_terminal(label)}  {row['objects']} object(s)  raw {_size(row['raw_bytes'])}  "
            f"stored {_size(row['stored_bytes'])}"
        )


def cmd_prune(args: argparse.Namespace) -> None:
    from opentine.repository._gc_prune import prune
    from opentine.repository._reflog_expire import expire_reflogs

    try:
        repo = _repo(args.repo)
        expired = expire_reflogs(repo.path, args.reflog_expire, dry_run=not args.delete)
        result = prune(
            repo,
            delete=args.delete,
            min_age=args.older_than * 86400,
            git_links=not args.no_git_links,
        )
    except (OSError, ValueError) as exc:  # KernelError is a ValueError
        _refuse(exc)
    summary = {**result.summary(), "dry_run": not args.delete, "reflog_rows_expired": expired}
    summary.pop("cutoff", None)
    if args.json:
        print(json.dumps(summary, sort_keys=True))
        return
    verb = "Deleted" if args.delete else "Would delete"
    console.print(
        f"[{BRAND}]# {verb}[/] {len(result.candidates) if not args.delete else result.deleted} "
        f"unreachable object(s), {_size(result.candidate_bytes)} "
        f"({result.unreachable} unreachable, {result.young} too recent, "
        f"{result.reachable} reachable kept)"
    )
    if not args.delete and result.candidates:
        console.print("  run again with --delete to remove them")


DU_COMMANDS = {"du": cmd_du, "prune": cmd_prune}
