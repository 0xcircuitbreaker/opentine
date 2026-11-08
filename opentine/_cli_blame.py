"""``tine blame`` parser, its git-compatible modes, ``tine why`` and ``tine attach`` (0.45).

* ``tine blame FILE --porcelain`` prints ``git blame --porcelain`` byte for
  byte, plus ``tine-run``/``tine-step``/``tine-model`` headers on agent lines
  (:mod:`opentine._blame_lines`). ``--lines`` is a readable per-line view and
  ``--lines --json`` the ``tine-blame/1`` record.
* ``tine why FILE:LINE`` follows the line to its commit, the commit's runs and
  attribution note, and prints the causal slice of the run that wrote it: the
  writing step and every step it descends from.
* ``tine attach RUN COMMIT`` links a run captured after the fact: it writes the
  run note and the line attribution note (signed with ``--sign-key``) and sets
  ``notes.rewriteRef`` so the link survives ``commit --amend`` and rebase.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from opentine._cli_common import _runs_dir, _terminal, console
from opentine._cli_errors import fail
from opentine._cli_json import emit
from opentine._cli_who_render import emit_or_print
from opentine._git_link import GitLinkError


def add_blame_parser(sub: Any) -> None:
    blame = sub.add_parser("blame", help="Which run, step and model wrote a file or line")
    blame.add_argument("target", metavar="PATH[:LINE]")
    blame.add_argument("--git", action="store_true", help="Go through git blame and commit links")
    blame.add_argument("--porcelain", action="store_true", help="git blame --porcelain, annotated")
    blame.add_argument("--line-porcelain", action="store_true", help="git blame --line-porcelain")
    blame.add_argument("--lines", action="store_true", help="Every line: commit, run, text")
    blame.add_argument("--rev", default="HEAD", help="Revision to blame (default HEAD)")
    blame.add_argument("-L", dest="line_range", default="", metavar="START,END")
    blame.add_argument("--repo", metavar="PATH", help="Read a v3 repository instead")
    blame.add_argument("--json", action="store_true")
    why = sub.add_parser("why", help="The causal run slice behind one line of a file")
    why.add_argument("target", metavar="FILE:LINE")
    why.add_argument("--repo", metavar="PATH", help="Read a v3 repository instead")
    why.add_argument("--json", action="store_true")
    attach = sub.add_parser("attach", help="Attach a run to a commit after the fact")
    attach.add_argument("run")
    attach.add_argument("commit")
    attach.add_argument("--sign-key", metavar="KEY", help="Ed25519 private key to sign with")
    attach.add_argument(
        "--no-configure", action="store_true", help="Do not set notes.rewriteRef in git config"
    )
    attach.add_argument("--repo", metavar="PATH", help="Read a v3 repository instead")
    attach.add_argument("--json", action="store_true")


def wants_lines(args: argparse.Namespace) -> bool:
    return bool(args.porcelain or args.line_porcelain or args.lines)


def cmd_blame_lines(args: argparse.Namespace) -> None:
    from opentine._blame_lines import annotate, blame_record, raw_blame

    cwd = Path.cwd()
    try:
        if args.porcelain or args.line_porcelain:
            raw = raw_blame(
                cwd, args.target, rev=args.rev, lines=args.line_range,
                line_porcelain=args.line_porcelain,
            )  # fmt: skip
            sys.stdout.flush()
            sys.stdout.buffer.write(annotate(cwd, raw))
            sys.stdout.buffer.flush()
            return
        record = blame_record(cwd, args.target, rev=args.rev, lines=args.line_range)
    except (GitLinkError, ValueError) as exc:
        fail(str(exc), 2)
    if args.json:
        emit(record)
        return
    for row in record["lines"]:
        run = (row["ai"] or {}).get("run") or "-"
        console.print(
            f"{row['commit'][:8] or '00000000'} {_terminal(run)[:20]:<20} "
            f"{row['line']:>5}) {_terminal(row['text'])}",
            markup=False,
            highlight=False,
        )


def _split(target: str) -> tuple[str, int]:
    path, _, text = target.rpartition(":")
    if not path or not text.isdigit() or int(text) < 1:
        fail("give FILE:LINE (lines start at 1)", 2)
    return path, int(text)


def _slice(run: Any, step_id: str, seq: Any) -> list[dict[str, Any]]:
    steps = list(run.steps)
    if not step_id and isinstance(seq, int) and 0 <= seq < len(steps):
        step_id = steps[seq].id
    if not step_id:
        return []
    order = {step.id: number for number, step in enumerate(steps)}
    chain = [*run.ancestors(step_id), run.get_step(step_id)]
    seen: dict[str, Any] = {step.id: step for step in chain if step is not None}
    return [
        {
            "seq": order.get(step.id),
            "step_id": step.id,
            "kind": str(getattr(step.kind, "value", step.kind)),
            "model": step.model_info,
            "tool": str((step.tool_info or {}).get("name", "")),
        }
        for step in sorted(seen.values(), key=lambda item: order.get(item.id, 0))
    ]


def cmd_why(args: argparse.Namespace) -> None:
    from opentine._blame import git_blame
    from opentine._blame_lines import _note_lines
    from opentine._git_link_runs import open_catalog

    path, line = _split(args.target)
    cwd = Path.cwd()
    try:
        catalog = open_catalog(getattr(args, "repo", None), _runs_dir())
        commit, linked, hits = git_blame(
            catalog.index, catalog.load, cwd, path, line, catalog.run_id
        )
    except (GitLinkError, OSError, ValueError) as exc:
        fail(str(exc), 2)
    found: dict[str, Any] = {}
    if commit:
        for name, lines in _note_lines(cwd, commit).items():
            if Path(name).as_posix() == Path(path).as_posix() and line in lines:
                found = lines[line]  # the note's own line number, valid at that commit
    run_name = found.get("run") or (hits[0].run_id if hits else "")
    step_id = next((hit.step_id for hit in hits if hit.run_id == run_name), "")
    steps: list[dict[str, Any]] = []
    if run_name:
        try:
            steps = _slice(catalog.load(run_name), step_id, found.get("seq"))
        except Exception:  # noqa: BLE001 - a run not held here has no slice to show
            steps = []
    payload = {
        "path": path, "line": line, "commit": commit, "linked_runs": linked,
        "run": run_name, "attribution": found or None, "slice": steps,
    }  # fmt: skip

    def human() -> None:
        if not run_name:
            console.print(f"{path}:{line}: no agent run is linked to this line.")
            return
        console.print(f"{path}:{line}  commit {commit[:12] or '-'}  run {_terminal(run_name)}")
        for step in steps:
            console.print(
                f"  step {step['seq']}  {step['kind']}  {_terminal(step['tool'] or step['model'])}",
                markup=False,
                highlight=False,
            )

    emit_or_print(args, "why", payload, human)


def cmd_attach(args: argparse.Namespace) -> None:
    from opentine._cli_attribute import HANDLERS

    args.runs = [args.run]
    HANDLERS["attribute"](args)


COMMANDS = {"why": cmd_why, "attach": cmd_attach}

__all__ = ["COMMANDS", "add_blame_parser", "cmd_blame_lines", "wants_lines"]
