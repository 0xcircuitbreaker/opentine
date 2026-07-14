"""Legacy file index listing, search, rebuild, and tag commands."""

from __future__ import annotations

import argparse

from rich.markup import escape

from opentine._cli_common import BRAND, _find_run, _index_update, _runs_dir, console
from opentine._cli_render import _entries_table, _has_filters, _query_from_ls_args
from opentine.core import Run, short_id
from opentine.index import QueryError, RunIndex, match_entry


def cmd_ls(args: argparse.Namespace) -> None:
    index = RunIndex.open(_runs_dir()).sync()
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
        results = RunIndex.open(_runs_dir()).search(query)
    except QueryError as exc:
        console.print(f"[red]Bad query:[/] {escape(str(exc))}")
        raise SystemExit(1) from exc
    if not results:
        console.print("[dim]No runs match.[/]")
        return
    console.print(_entries_table(f"Search: {query or '*'}", results, show_unreadable=False))


def cmd_reindex(args: argparse.Namespace) -> None:
    del args
    index = RunIndex.open(_runs_dir()).reindex()
    unreadable = sum(1 for entry in index.entries.values() if entry.unreadable)
    console.print(
        f"[{BRAND}]# Reindexed[/] {len(index.entries)} run(s), "
        f"{unreadable} unreadable -> {index.path}"
    )


def cmd_tag(args: argparse.Namespace) -> None:
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {args.run_id}[/]")
        raise SystemExit(1)
    run = Run.load(path)
    if args.list or (not args.add and not args.remove):
        console.print(", ".join(run.tags) if run.tags else "[dim](no tags)[/]")
        return
    changed = False
    for tag in args.add or []:
        changed |= run.add_tag(tag)
    for tag in args.remove or []:
        changed |= run.remove_tag(tag)
    if changed:
        run.save(path)
        _index_update(path)
    console.print(f"[{BRAND}]# Tags[/] {short_id(run.id)}: {', '.join(run.tags) or '(none)'}")
