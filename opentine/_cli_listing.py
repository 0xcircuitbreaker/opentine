"""Legacy file index listing, search, rebuild, and tag commands."""

from __future__ import annotations

import argparse

from opentine._artifact_io import artifact_integrity, read_artifact_json
from opentine._cli_common import BRAND, _find_run, _index_update, _runs_dir, _terminal, console
from opentine._cli_render import _entries_table, _has_filters, _query_from_ls_args
from opentine.core import Run, short_id
from opentine.index import MAX_INDEX_RUNS, QueryError, RunIndex, match_entry


def _index(rebuild: bool = False) -> RunIndex:
    """Open the run index, reporting an over-cap runs directory as an error.

    Past MAX_INDEX_RUNS artifacts the index refuses to build. That is a bounded-work
    guard, not a bug — but it reached the user as an interpreter traceback from an
    ordinary ``tine ls``, with nothing said about how to recover.
    """
    opened = RunIndex.open(_runs_dir())
    try:
        return opened.reindex() if rebuild else opened.sync()
    except ValueError as exc:
        # Report the limit that actually fired. The index enforces several
        # (artifact count, aggregate source bytes, serialized size), and naming
        # the count cap unconditionally sent users to archive files when the real
        # cause was a single oversized run.
        console.print(
            f"[red]Cannot index runs:[/] {_terminal(exc)}. "
            f"Move the offending .tine files out of {_terminal(_runs_dir())} "
            f"(the artifact-count cap is {MAX_INDEX_RUNS})."
        )
        raise SystemExit(1) from exc


def cmd_ls(args: argparse.Namespace) -> None:
    index = _index()
    if not index.entries:
        console.print("[dim]No runs found. Use tine run <script.py> to create one.[/]")
        return
    query = _query_from_ls_args(args)
    filtering = _has_filters(query)
    readable = [
        entry
        for entry in index.entries.values()
        if not entry.unreadable and match_entry(entry, query)
    ]
    readable.sort(key=lambda entry: entry.created_at, reverse=True)
    rows = readable[: args.limit or 20]
    if not filtering:
        rows.extend(entry for entry in index.entries.values() if entry.unreadable)
    if filtering and not readable:
        console.print("[dim]No runs match the given filters.[/]")
        return
    console.print(_entries_table("Recent Runs", rows, show_unreadable=not filtering))


def cmd_search(args: argparse.Namespace) -> None:
    query = " ".join(args.query)
    try:
        results = _index().search(query)
    except QueryError as exc:
        console.print(f"[red]Bad query:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    if not results:
        console.print("[dim]No runs match.[/]")
        return
    console.print(_entries_table(f"Search: {query or '*'}", results, show_unreadable=False))


def cmd_reindex(args: argparse.Namespace) -> None:
    del args
    index = _index(rebuild=True)
    unreadable = sum(1 for entry in index.entries.values() if entry.unreadable)
    console.print(
        f"[{BRAND}]# Reindexed[/] {len(index.entries)} run(s), "
        f"{unreadable} unreadable -> {index.path}"
    )


def cmd_tag(args: argparse.Namespace) -> None:
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {_terminal(args.run_id)}[/]")
        raise SystemExit(1)
    run = Run.load(path)
    if args.list or (not args.add and not args.remove):
        console.print(_terminal(", ".join(run.tags)) if run.tags else "[dim](no tags)[/]")
        return
    changed = False
    for tag in args.add or []:
        changed |= run.add_tag(tag)
    for tag in args.remove or []:
        changed |= run.remove_tag(tag)
    if changed:
        # A plain re-save deliberately strips any signature (re-signing must be an
        # explicit act), but tagging is an ordinary edit a user does not expect to
        # de-authenticate the artifact. Say so rather than let it happen silently.
        signed = bool((artifact_integrity(read_artifact_json(path)) or {}).get("signature"))
        run.save(path)
        _index_update(path)
        if signed:
            console.print(
                "[yellow]Signature removed[/] by this edit; "
                "re-run [bold]tine sign[/] to restore it."
            )
    console.print(
        f"[{BRAND}]# Tags[/] {_terminal(short_id(run.id))}: "
        f"{_terminal(', '.join(run.tags) or '(none)')}"
    )
