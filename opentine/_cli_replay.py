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
from opentine._cli_flags import HARNESS_CONFIG_FLAGS, _require_output_slot, refuse_unhonoured
from opentine._cli_render import _print_diff_table, _print_run_tree
from opentine._cli_verify_replay import cache_replay, expected_slice, verify_replay
from opentine.core import Run
from opentine.harnesses import OpentineHarness


def _inspect_replay(run: Run, from_step: str | None) -> None:
    """Preview exactly the slice the replay would retain.

    This previewed ``graph.descendant_closure(start)`` — the steps *after* the
    fork point — while ``Run.fork`` retains the ANCESTOR closure, the steps that
    led *to* it. So `--inspect`/`--dry-run` listed the complement of what the
    replay reuses on any branched run, and agreed only by accident on a linear
    one. Both now read ``expected_slice``, the same helper ``--verify`` states
    its expectation with, so a preview and the replay cannot disagree again.
    """
    selected: list = []
    if run.steps:
        _, retained = expected_slice(run, from_step)
        selected = [step for step in run.steps if step.id in retained]
    console.print(f"[{BRAND}]Inspecting recorded steps...[/]\n")
    for step in selected:
        console.print(Text("  ") + _step_label(step))
    console.print(f"\n[{BRAND}]# Cached replay[/] would reuse {len(selected)} recorded steps")


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
            (
                "compare",
                "force",
                "harness",
                "ignore_cost_drift",
                "json",
                "mode",
                "prompt",
                "save",
                "verify",
                *HARNESS_CONFIG_FLAGS,
            ),
            mode="with --inspect/--dry-run",
            hint="Inspection only lists the recorded steps; drop it to replay for real.",
        )
        return
    if not args.verify:
        refuse_unhonoured(
            args,
            ("ignore_cost_drift", "json"),
            mode="without --verify",
            hint="Both describe the verification verdict; a plain replay only writes the run.",
        )
    if not args.harness:
        refuse_unhonoured(
            args,
            ("compare", "prompt", *HARNESS_CONFIG_FLAGS),
            mode="for a cached replay",
            hint="Pass --harness to re-execute the run instead of reusing its steps.",
        )


def cmd_replay(args: argparse.Namespace) -> None:
    """Inspect, cache-replay, harness-replay, or (``--verify``) check a replay.

    Known status divergence, documented rather than changed in 0.6.0: a cached
    replay here carries the *source's* status (a replay of a failed run is a
    replay of a failure), while ``HistoryMixin.replay`` — the ``Agent`` API —
    marks its cached replay ``completed``. ``tine replay --verify`` checks this
    path, so it pins the CLI behaviour; reconciling the two is a 0.7.0 change.
    """
    _refuse_ignored_replay_flags(args)
    if args.verify:
        # --verify owns its own lookup, load, temp workspace and exit status, and
        # writes an artifact only when --save asks for one.
        verify_replay(args)
        return
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
        # One source of truth with --verify, which checks this exact artifact.
        replayed = cache_replay(run, _resolve_step_ref(run, args.from_step))
    except (KeyError, ValueError) as exc:
        console.print(f"[red]{_terminal(exc)}[/]")
        raise SystemExit(1) from exc
    output = Path(args.save) if args.save else _runs_dir() / f"{replayed.id}.tine"
    _require_output_slot(output, getattr(args, "force", False))
    replayed.save(output)
    console.print(f"[{BRAND}]# Cached replay[/] reused {len(replayed.steps)} recorded steps")
