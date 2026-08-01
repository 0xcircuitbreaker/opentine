"""Replay command: inspection, cached replay, and harness re-execution."""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.text import Text

from opentine._cli_common import (
    BRAND,
    _find_run,
    _harness_from_args,
    _resolve_step_ref,
    _run_context,
    _runs_dir,
    _step_label,
    _terminal,
    console,
)
from opentine._cli_flags import HARNESS_CONFIG_FLAGS, refuse_unhonoured
from opentine._cli_flow import _require_output_slot
from opentine._cli_render import _print_diff_table, _print_run_tree
from opentine.core import Run
from opentine.harnesses import OpentineHarness


def _inspect_replay(run: Run, from_step: str | None) -> None:
    selected = run.steps
    if from_step is not None:
        start = _resolve_step_ref(run, from_step)
        keep = run.graph.descendant_closure(start)
        selected = [step for step in run.steps if step.id in keep]
    console.print(f"[{BRAND}]Inspecting recorded steps...[/]\n")
    for step in selected:
        console.print(Text("  ") + _step_label(step))


def _harness_replay(args: argparse.Namespace, run: Run) -> None:
    task = args.prompt or run.user_prompt
    if not task:
        console.print("[red]--prompt is required when replaying a harness run.[/]")
        raise SystemExit(1)
    start = _resolve_step_ref(run, args.from_step) if args.from_step is not None else None
    wrapper = OpentineHarness(_harness_from_args(args))
    output = Path(args.save) if args.save else None
    force = getattr(args, "force", False)
    if output is not None:
        _require_output_slot(output, force)
    try:
        replayed = wrapper.run_sync(task, context=_run_context(run, start), save_path=output)
    except Exception as exc:
        replayed = wrapper.run
        if replayed is not None:
            if output is None:
                output = _runs_dir() / f"{replayed.id}.tine"
                _require_output_slot(output, force)
            if not output.exists():
                replayed.save(output)
        console.print(f"[red]Harness replay failed:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    if output is None:
        output = _runs_dir() / f"{replayed.id}.tine"
        _require_output_slot(output, force)
        replayed.save(output)
    console.print(f"[{BRAND}]# Replayed[/] {_terminal(run.id)} with {_terminal(args.harness)}")
    _print_run_tree(replayed)
    if args.compare:
        _print_diff_table(run, replayed)


def _refuse_ignored_replay_flags(args: argparse.Namespace) -> None:
    if args.inspect or args.dry_run:
        refuse_unhonoured(
            args,
            ("compare", "force", "harness", "mode", "prompt", "save", *HARNESS_CONFIG_FLAGS),
            mode="with --inspect/--dry-run",
            hint="Inspection only lists the recorded steps; drop it to replay for real.",
        )
    elif not args.harness:
        refuse_unhonoured(
            args,
            ("compare", "prompt", *HARNESS_CONFIG_FLAGS),
            mode="for a cached replay",
            hint="Pass --harness to re-execute the run instead of reusing its steps.",
        )


def cmd_replay(args: argparse.Namespace) -> None:
    _refuse_ignored_replay_flags(args)
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {_terminal(args.run_id)}[/]")
        raise SystemExit(1)
    run = Run.load(path)
    try:
        if args.inspect or args.dry_run:
            _inspect_replay(run, args.from_step)
            return
        if args.harness:
            _harness_replay(args, run)
            return
        if args.mode == "rerun":
            console.print(
                "[red]Rerun replay requires an explicit --harness or opentine-native Agent API.[/]"
            )
            raise SystemExit(1)
        # A cached replay only reuses recorded steps, so it is an idempotent act:
        # nonce="" keeps the id reproducible, which is exactly what makes a second
        # replay resolve to the same path and hit the overwrite refusal (the property
        # pinned by test_cached_replay_never_derives_an_output_path_from_untrusted_run_id).
        replayed = run.fork(
            _resolve_step_ref(run, args.from_step), intent={"replay": "cache"}, nonce=""
        )
    except (KeyError, ValueError) as exc:
        console.print(f"[red]{_terminal(exc)}[/]")
        raise SystemExit(1) from exc
    replayed.metadata["replay"] = {
        "mode": "cache",
        "reused_steps": len(replayed.steps),
        "source_run": run.id,
    }
    replayed.status = run.status
    output = Path(args.save) if args.save else _runs_dir() / f"{replayed.id}.tine"
    _require_output_slot(output, getattr(args, "force", False))
    replayed.save(output)
    console.print(f"[{BRAND}]# Cached replay[/] reused {len(replayed.steps)} recorded steps")
