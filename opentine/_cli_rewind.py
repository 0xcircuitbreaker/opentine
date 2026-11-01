"""``tine rewind RUN[@STEP]``: restore the files a run changed, as of a step.

A dry run by default: it lists what would change, what cannot be recovered
from the run (and why), what lies outside the target root, and what the user
changed since the run. ``--apply`` writes atomically and refuses every write
when any file has changed since the run, unless ``--force``.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._cli_common import _find_run, _resolve_step_ref, _terminal, console
from opentine._cli_who_render import emit_or_print
from opentine._codec_io import atomic_write_bytes
from opentine._rewind import (
    Event,
    Plan,
    RewindError,
    backward,
    confined,
    forward,
    histories,
    plan_file,
)


def add_rewind_parser(sub: Any) -> None:
    rewind = sub.add_parser(
        "rewind", help="Restore the files a run changed to how they were at a step"
    )
    rewind.add_argument(
        "target", metavar="RUN[@STEP]", help="Run, and the step to rewind to (default: before it)"
    )
    rewind.add_argument("--root", metavar="DIR", help="Working tree to restore (default: cwd)")
    rewind.add_argument("--apply", action="store_true", help="Write the files (default: dry run)")
    rewind.add_argument(
        "--force", action="store_true", help="Also overwrite files changed since the run"
    )
    rewind.add_argument("--json", action="store_true")


def _fail(message: str) -> None:
    console.print(f"[red]{_terminal(message)}[/]")
    raise SystemExit(2)


def _read(path: Path) -> str | None:
    try:
        return path.read_bytes().decode("utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError):
        return "\0unreadable"


def redo(state: str, edits: list) -> str | None:
    return forward(state, Event(0, "edit", edits))


def _decide(plan: Plan, current: str | None, force: bool) -> tuple[str, str, str | None]:
    """``(status, reason, content to write)`` for one recoverable file."""
    if plan.reverse_on_disk is not None:
        if current is None:
            return "unrecoverable", "missing, and the run recorded only edits to it", None
        target = backward(current, plan.reverse_on_disk)
        if target is None and redo(current, plan.reverse_on_disk) is not None:
            return "unchanged", "", None  # the run's edits are already undone
        if target is None:
            return "unrecoverable", "the run's edits are no longer in it exactly once", None
        return ("unchanged", "", None) if target == current else ("restore", "", target)
    target = plan.target
    if current == target:
        return "unchanged", "", None
    if plan.final is not None and current == plan.final:
        return "restore", "", target
    if plan.final is None:
        reason = "the run's last content is not recorded, so a later change cannot be ruled out"
    else:
        reason = "missing now" if current is None else "changed since the run"
    return ("restore", f"forced: {reason}", target) if force else ("conflict", reason, None)


def cmd_rewind(args: argparse.Namespace) -> None:
    from opentine.graph import Run

    name, at, step_ref = args.target.rpartition("@") if "@" in args.target else ("", "", "")
    name = name if at else args.target
    found = _find_run(name)
    if found is None:
        _fail(f"No run matches {name}")
    try:
        run = Run.load(found)
        step_id = _resolve_step_ref(run, step_ref) if step_ref else ""
    except (OSError, ValueError, KeyError) as exc:
        _fail(f"Cannot read {name}: {exc}")
        raise  # unreachable
    until = next((i for i, step in enumerate(run.steps) if step.id == step_id), -1)
    root = Path(args.root or ".").resolve()
    rows: dict[str, list[dict[str, Any]]] = {
        key: [] for key in ("restore", "unchanged", "conflict", "unrecoverable", "refused")
    }
    writes: list[tuple[Path, str]] = []
    for key, events in sorted(histories(run, root).items()):
        shown = key[len(root.as_posix()) + 1 :] if key.startswith(root.as_posix() + "/") else key
        try:
            path = confined(root, key)
        except RewindError as exc:
            rows["refused"].append({"path": shown, "reason": str(exc)})
            continue
        plan = plan_file(key, events, until)
        if plan.target is None and plan.reverse_on_disk is None:
            rows["unrecoverable"].append({"path": shown, "reason": plan.reason})
            continue
        status, reason, content = _decide(plan, _read(path), args.force)
        rows[status].append({"path": shown, "reason": reason})
        if content is not None:
            writes.append((path, content))
    blocked = bool(rows["conflict"])
    applied = bool(args.apply) and not blocked
    if applied:
        for path, content in writes:
            atomic_write_bytes(path, content.encode("utf-8"))
    payload = {
        "run": run.id,
        "step": step_id or None,
        "step_index": until,
        "root": root.as_posix(),
        "dry_run": not args.apply,
        "applied": applied,
        **{status: entries for status, entries in rows.items()},
    }
    emit_or_print(args, "rewind", payload, lambda: _human(payload, args.apply, blocked))
    if args.apply and blocked:
        raise SystemExit(1)


def _human(payload: dict[str, Any], apply: bool, blocked: bool) -> None:
    verb = "Restored" if payload["applied"] else "Would restore"
    labels = {
        "restore": verb,
        "conflict": "Changed since the run (use --force)",
        "unrecoverable": "Cannot recover from the run",
        "refused": "Refused (outside the root)",
    }
    for status, label in labels.items():
        for row in payload[status]:
            extra = f"  ({row['reason']})" if row["reason"] else ""
            console.print(f"{label}: {_terminal(row['path'])}{_terminal(extra)}")
    if not any(payload[status] for status in labels):
        console.print("Nothing to rewind.")
    if apply and blocked:
        console.print("[red]Nothing written: files changed since the run.[/]")
    elif not apply and payload["restore"]:
        console.print("Dry run; pass --apply to write.")


COMMANDS = {"rewind": cmd_rewind}

__all__ = ["COMMANDS", "add_rewind_parser", "cmd_rewind"]
