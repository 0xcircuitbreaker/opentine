"""Fork, diff, and resume commands."""

from __future__ import annotations

import argparse
from pathlib import Path

from opentine._cli_common import (
    BRAND,
    _find_run,
    _harness_from_args,
    _resolve_step_ref,
    _run_context,
    _runs_dir,
    _terminal,
    console,
)
from opentine._cli_flags import HARNESS_CONFIG_FLAGS, _require_output_slot, refuse_unhonoured
from opentine._cli_json_flow import drift_payload, emit_diff, identical
from opentine._cli_render import _print_diff_table, _print_run_tree
from opentine.core import Run, short_id
from opentine.harnesses import OpentineHarness


def _refuse_ignored_fork_flags(args: argparse.Namespace) -> None:
    if not args.harness:
        refuse_unhonoured(
            args,
            ("prompt", *HARNESS_CONFIG_FLAGS),
            mode="without --harness",
            hint="A plain fork only copies recorded steps; add --harness with --prompt.",
        )
    elif not args.prompt:
        refuse_unhonoured(
            args,
            HARNESS_CONFIG_FLAGS,
            mode="without --prompt",
            hint="--harness alone only records the harness to continue with later.",
        )


def cmd_fork(args: argparse.Namespace) -> None:
    _refuse_ignored_fork_flags(args)
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {_terminal(args.run_id)}[/]")
        raise SystemExit(1)
    run = Run.load(path)
    try:
        step_id = _resolve_step_ref(run, args.from_step)
    except (KeyError, ValueError) as exc:
        console.print(f"[red]{_terminal(exc)}[/]")
        raise SystemExit(1) from exc
    step = run.get_step(step_id)
    if step is None:
        console.print(f"[red]Step not found: {_terminal(step_id)}[/]")
        raise SystemExit(1)
    forked = run.fork(step.id, intent={"harness": args.harness, "prompt": args.prompt})
    output = Path(args.save or (_runs_dir() / f"{forked.id}.tine"))
    _require_output_slot(output, args.force)
    if args.harness:
        forked.metadata["next_harness"] = args.harness
        if args.prompt:
            wrapper = OpentineHarness(_harness_from_args(args), run=forked)
            try:
                forked = wrapper.run_sync(
                    args.prompt,
                    context={
                        **_run_context(run, from_step=step.id),
                        "fork_point": step.id,
                        "forked_from": run.id,
                    },
                    save_path=output,
                )
            except Exception as exc:
                forked.save(output)
                console.print(f"[red]Harness failed after fork:[/] {_terminal(exc)}")
                raise SystemExit(1) from exc
    forked.save(output)
    console.print(
        f"[{BRAND}]# Forked[/] {_terminal(short_id(run.id))} -> "
        f"{_terminal(short_id(forked.id))} from {_terminal(short_id(step.id))}"
    )
    _print_run_tree(forked)


def cmd_diff(args: argparse.Namespace) -> None:
    """Compare two legacy artifacts: the table by default, JSON and a status on request.

    The comparison is only computed for the flags that need it, so a plain
    ``tine diff`` is exactly the table it has always printed and still exits 0 —
    the drift object and the exit status are additions, not a new default.
    """
    left, right = _find_run(args.run_a), _find_run(args.run_b)
    if not left or not right:
        missing = args.run_a if not left else args.run_b
        console.print(f"[red]Run not found: {_terminal(missing)}[/]")
        raise SystemExit(1)
    as_json, gate = getattr(args, "json", False), getattr(args, "exit_code", False)
    left_run, right_run = Run.load(left), Run.load(right)
    comparison = left_run.diff(right_run) if as_json or gate else None
    if as_json:
        same = emit_diff(left_run, right_run, (left, right), comparison)
    else:
        _print_diff_table(left_run, right_run)
        same = comparison is None or identical(drift_payload(comparison))
    # git-diff semantics, and only ever 1: argparse owns 2 for a usage error.
    if gate and not same:
        raise SystemExit(1)


def cmd_resume(args: argparse.Namespace) -> None:
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {_terminal(args.run_id)}[/]")
        raise SystemExit(1)
    run = Run.load(path)
    if not run.manifest.get("resume", False):
        kind = run.manifest.get("kind", "unknown")
        console.print(f"[red]Run is not resumable: manifest kind={_terminal(repr(kind))}.[/]")
        raise SystemExit(1)
    resumed = Run.resume(path)
    console.print(
        f"[{BRAND}]# Loaded resumable run[/] {_terminal(short_id(resumed.id))} "
        f"({len(resumed.steps)} steps)"
    )
    _print_run_tree(resumed)
    resumed.save(path)
