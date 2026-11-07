"""``tine import REPO --format entire --all --repo PATH``: every Entire checkpoint.

Each session of each checkpoint the source repository holds (per-checkpoint
refs first, then the ``entire/checkpoints/v1`` branch for any id not already
seen; see :mod:`opentine.trace._entire_refs`) becomes its own run, recorded on
``heads/entire/<checkpoint, lowercased>/<session>`` in ``--repo``, so a
re-import of the same checkpoint advances the same ref. The events go through
the same billing, pricing and capture steps as a single ``tine import``.

With ``--json`` one object is written::

    {"command": "import", "format": "entire", "all": true,
     "runs": [{"checkpoint_id", "session_index", "ref", "run_id", "events_imported"}]}
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from opentine._cli_common import BRAND, _terminal, console

ALL_HELP = "Entire: import every checkpoint session, one run each (needs --repo)"


def _refuse(message: str) -> SystemExit:
    console.print(f"[red]{message}[/]")
    return SystemExit(1)


def _check(args: argparse.Namespace) -> None:
    if args.format not in ("auto", "entire"):
        raise _refuse("--all imports Entire checkpoints: use it with --format entire.")
    if not args.repo or args.save or args.ref is not None or getattr(args, "fleet", False):
        raise _refuse(
            "--all records one run per checkpoint session into a repository: "
            "pass --repo PATH, and no --save, --ref or --fleet."
        )
    if args.source is None or "::" in str(args.source) or not Path(args.source).is_dir():
        raise _refuse("--all reads a git repository directory, without ::CHECKPOINT.")


def _events(events: list[Any], price: bool) -> list[Any]:
    from opentine._import_billing import distrust_source_billing, mark_unpriced
    from opentine._pricing_pass import price_events

    events = distrust_source_billing(events)
    return mark_unpriced(price_events(events) if price else events)


def _import(args: argparse.Namespace) -> list[dict[str, Any]]:
    from opentine._git_link import GitLinkError
    from opentine._import_write import record
    from opentine.repo import Repo
    from opentine.trace import _entire_refs as er
    from opentine.trace._import_entire import FORMAT, session_dirs, session_events
    from opentine.trace._transcript_common import capture_marker

    source, repo = Path(args.source), Repo.open(args.repo)
    rows = []
    try:
        for where in er.all_locations(source):
            for index in range(len(session_dirs(source, where))):
                events = _events(session_events(source, where, index), args.price)
                ref = f"heads/entire/{where.checkpoint.lower()}/{index}"
                run_id = record(repo, events, ref, capture_marker(FORMAT), FORMAT)
                row = {"checkpoint_id": where.checkpoint, "session_index": index, "ref": ref}
                rows.append({**row, "run_id": run_id, "events_imported": len(events)})
    except GitLinkError as exc:
        raise ValueError(f"git: {exc}") from exc
    return rows


def import_entire_all(args: argparse.Namespace) -> bool:
    """Run ``--all`` when it was given; ``False`` leaves the import to cmd_import."""
    if not getattr(args, "all", False):
        return False
    _check(args)
    try:
        rows = _import(args)
    except (OSError, RecursionError, ValueError) as exc:
        console.print(f"[red]Import failed:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    if getattr(args, "json", False):
        out = {"command": "import", "format": "entire", "all": True, "runs": rows}
        sys.stdout.write(json.dumps(out, sort_keys=True) + "\n")
        return True
    console.print(f"[{BRAND}]# Imported[/] {len(rows)} Entire checkpoint session(s)")
    for row in rows:
        console.print(
            f"  {_terminal(row['ref'])} -> {_terminal(row['run_id'])} "
            f"({row['events_imported']} event(s))"
        )
    return True


__all__ = ["ALL_HELP", "import_entire_all"]
