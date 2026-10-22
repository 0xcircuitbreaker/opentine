"""``tine git ...`` (hook, notes, commit → runs) and ``tine blame``."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._blame import blame, git_blame
from opentine._cli_common import RUNS_DIR, _runs_dir, _terminal, console
from opentine._cli_who_render import emit_or_print
from opentine._git_link import (
    RUN_ID,
    GitLinkError,
    NoteEntry,
    commit_runs,
    pr_commits,
    resolve_commit,
    top_level,
    trailer_runs,
    write_note,
)
from opentine._git_link_hook import (
    add_trailers,
    configured_source,
    install_hook,
    last_commit_time,
    record_source,
    runs_for_staged,
    staged_paths,
)
from opentine._git_link_runs import RunCatalog, open_catalog, run_summary


def _fail(message: str) -> None:
    console.print(f"[red]{_terminal(message)}[/]")
    raise SystemExit(2)


def _catalog(args: argparse.Namespace) -> RunCatalog:
    try:
        return open_catalog(getattr(args, "repo", None), _runs_dir())
    except (OSError, ValueError) as exc:
        _fail(f"Cannot index runs: {exc}")
        raise  # unreachable


def cmd_git(args: argparse.Namespace) -> None:
    handler = {
        "install-hook": _install_hook,
        "note": _note,
        "log": _log,
        "trailers": _trailers,
    }.get(args.git_command)
    if handler is None:
        _fail("usage: tine git {install-hook,note,log,trailers}")
    try:
        handler(args)
    except GitLinkError as exc:
        _fail(str(exc))


def _install_hook(args: argparse.Namespace) -> None:
    cwd = Path.cwd()
    repo, runs_dir = args.repo or "", args.runs_dir or ""
    if not (repo or runs_dir or args.global_):
        # Chosen by the user running install here, not read later from a clone.
        repo = str(cwd / ".tine") if (cwd / ".tine").is_dir() else ""
        runs_dir = "" if repo else str(cwd / RUNS_DIR)
    hook = install_hook(cwd, global_=args.global_)
    record_source(cwd, repo=repo, runs_dir=runs_dir, global_=args.global_)
    emit_or_print(
        args,
        "git install-hook",
        {"hook": str(hook), "global": bool(args.global_), "repo": repo, "runs_dir": runs_dir},
        lambda: console.print(f"Installed prepare-commit-msg hook: {_terminal(str(hook))}"),
    )


def _trailers(args: argparse.Namespace) -> None:
    """Called by the hook: append Tine-Run trailers for runs that wrote staged files."""
    if args.source in ("merge", "squash"):
        return
    cwd = Path.cwd()
    root = top_level(cwd)
    repo, runs_dir = configured_source(cwd)
    if not repo and not (runs_dir and Path(runs_dir).is_dir()):
        return  # nothing configured: never fall back to the working tree's own runs
    catalog = open_catalog(repo or None, Path(runs_dir))
    runs = runs_for_staged(catalog.index, root, staged_paths(cwd), last_commit_time(cwd))
    # Only well-formed run ids reach the commit message: a newline in an id must
    # never add a forged trailer such as Signed-off-by.
    names = [n for n in (catalog.canonical(run) for run in runs) if RUN_ID.fullmatch(n)]
    if names:
        add_trailers(cwd, Path(args.message_file), names)


def _note(args: argparse.Namespace) -> None:
    cwd = Path.cwd()
    sha = resolve_commit(cwd, args.commit)
    names = list(args.runs) or trailer_runs(cwd, sha)
    bad = [name for name in names if not RUN_ID.fullmatch(name)]
    if bad:
        _fail(f"not a run id: {bad[0][:80]!r}")
    if not names:
        _fail("no runs given and the commit has no Tine-Run trailers")
    catalog = _catalog(args)
    entries = []
    for name in names:
        info = run_summary(catalog, catalog.canonical(name) if catalog.known(name) else name)
        entries.append(
            NoteEntry(
                info["run"], str(info.get("model", "")), info.get("cost") if info["found"] else None
            )
        )
    linked = write_note(cwd, sha, entries)
    emit_or_print(
        args,
        "git note",
        {"commit": sha, "runs": linked},
        lambda: console.print(f"Noted {len(linked)} run(s) on {sha[:12]} under refs/notes/tine"),
    )


def _log(args: argparse.Namespace) -> None:
    cwd = Path.cwd()
    if bool(args.commit) == bool(args.pr):
        _fail("give exactly one of --commit SHA or --pr N")
    shas = [resolve_commit(cwd, args.commit)] if args.commit else pr_commits(cwd, args.pr)
    catalog = _catalog(args)
    rows: list[dict[str, Any]] = []
    for sha in shas:
        for name, source in commit_runs(cwd, sha):
            rows.append({"commit": sha, "source": source, **run_summary(catalog, name)})

    def human() -> None:
        if not rows:
            console.print("No runs are linked to that change.")
        for row in rows:
            detail = (
                f"{_terminal(row.get('model', ''))}  ${row.get('cost', 0):.4f}"
                if row["found"]
                else "[dim]not in this scope[/]"
            )
            console.print(
                f"{row['commit'][:12]}  {_terminal(row['run'])}  ({row['source']})  {detail}"
            )

    emit_or_print(args, "git log", {"commits": shas, "runs": rows}, human)


def cmd_blame(args: argparse.Namespace) -> None:
    path, _, line_text = (
        args.target.rpartition(":") if ":" in args.target else (args.target, "", "")
    )
    if not path or (line_text and not line_text.isdigit()):
        path, line_text = args.target, ""
    line = int(line_text) if line_text else None
    if line is not None and line < 1:
        _fail("line numbers start at 1")
    catalog = _catalog(args)
    commit, linked = "", []
    try:
        if args.git:
            if line is None:
                _fail("--git needs PATH:LINE")
            commit, linked, hits = git_blame(
                catalog.index, catalog.load, Path.cwd(), path, line, catalog.run_id
            )
        else:
            hits = blame(catalog.index, catalog.load, path, line=line)
    except GitLinkError as exc:
        _fail(str(exc))
    for hit in hits:
        hit.run_id = catalog.canonical(hit.run_id)
    payload = {
        "path": path,
        "line": line,
        "commit": commit,
        "linked_runs": linked,
        "hits": [hit.to_dict() for hit in hits],
    }

    def human() -> None:
        if commit:
            console.print(f"commit {commit[:12]}: {len(linked)} linked run(s)")
        if not hits:
            console.print("No recorded agent write matches.")
        for hit in hits:
            console.print(
                f"{_terminal(hit.run_id)}  step {hit.seq} ({_terminal(hit.step_id[:12])})  "
                f"{_terminal(hit.tool)}  {_terminal(hit.model)}  "
                f"{_terminal(hit.agent)}  [{hit.match}]"
            )

    emit_or_print(args, "blame", payload, human)


def add_gitlink_parsers(sub: Any) -> None:
    group = sub.add_parser("git", help="Link runs to git commits: hook, notes, commit → runs")
    git_sub = group.add_subparsers(dest="git_command")
    install = git_sub.add_parser("install-hook", help="Add Tine-Run trailers to commit messages")
    install.add_argument("--global", dest="global_", action="store_true", help="For every repo")
    install.add_argument("--repo", metavar="PATH", help="v3 repository the hook reads runs from")
    install.add_argument("--runs-dir", metavar="PATH", help="Runs directory the hook reads")
    install.add_argument("--json", action="store_true")
    note = git_sub.add_parser("note", help="Record runs on a commit under refs/notes/tine")
    note.add_argument("commit")
    note.add_argument("runs", nargs="*", help="Run ids (default: the commit's Tine-Run trailers)")
    log = git_sub.add_parser("log", help="The runs behind a commit or a GitHub PR")
    log.add_argument("--commit")
    log.add_argument("--pr", type=int)
    trailers = git_sub.add_parser("trailers", help=argparse.SUPPRESS)
    trailers.add_argument("message_file")
    trailers.add_argument("source", nargs="?", default="")
    trailers.add_argument("sha", nargs="?", default="")
    for parser in (note, log, trailers):
        parser.add_argument("--repo", metavar="PATH", help="Read a v3 repository instead")
        parser.add_argument("--json", action="store_true")
    blame_parser = sub.add_parser("blame", help="Which run, step and model wrote a file or line")
    blame_parser.add_argument("target", metavar="PATH[:LINE]")
    blame_parser.add_argument(
        "--git", action="store_true", help="Go through git blame and commit links"
    )
    blame_parser.add_argument("--repo", metavar="PATH", help="Read a v3 repository instead")
    blame_parser.add_argument("--json", action="store_true")


COMMANDS = {"git": cmd_git, "blame": cmd_blame}

__all__ = ["COMMANDS", "add_gitlink_parsers", "cmd_blame", "cmd_git"]
