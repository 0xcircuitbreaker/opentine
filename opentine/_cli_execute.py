"""Run, show, and cost commands."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

from rich.table import Table

from opentine._cli_common import (
    BRAND,
    BRAND_DIM,
    _cost_str,
    _find_run,
    _harness_from_args,
    _runs_dir,
    _terminal,
    console,
)
from opentine._cli_flags import AUTOSAVE_FLAGS, HARNESS_CONFIG_FLAGS, refuse_unhonoured
from opentine._cli_render import _budget_str, _print_run_tree
from opentine.core import Run, short_id
from opentine.harnesses import OpentineHarness


def cmd_run(args: argparse.Namespace) -> None:
    if args.harness:
        cmd_run_harness(args)
        return
    if not args.script:
        console.print("[red]Provide a Python script or use --harness with --prompt.[/]")
        raise SystemExit(1)
    refuse_unhonoured(
        args,
        (*AUTOSAVE_FLAGS, "prompt", *HARNESS_CONFIG_FLAGS),
        mode="without --harness",
        hint=(
            "A script builds its own Run, which tine sees only once the script has "
            "finished; use --save PATH to choose where that run is written."
        ),
    )
    script = Path(args.script)
    if not script.exists():
        console.print(f"[red]File not found: {_terminal(script)}[/]")
        raise SystemExit(1)
    console.print(f"[{BRAND}]# Running {_terminal(script.name)}...[/]\n")
    spec = importlib.util.spec_from_file_location("__tine_script__", str(script))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["__tine_script__"] = module
    spec.loader.exec_module(module)
    run = next(
        (getattr(module, name) for name in dir(module) if isinstance(getattr(module, name), Run)),
        None,
    )
    if run is None:
        console.print("[red]No Run object found in script.[/]")
        raise SystemExit(1)
    output = Path(args.save) if args.save else _runs_dir() / f"{run.id}.tine"
    run.save(output)
    console.print(f"\n[{BRAND}]Saved:[/] {_terminal(output)}")
    _print_run_tree(run)


def cmd_run_harness(args: argparse.Namespace) -> None:
    task = args.prompt or args.script
    if not task:
        console.print("[red]--prompt is required when running a harness.[/]")
        raise SystemExit(1)
    autosave_path = getattr(args, "autosave", None)
    if not autosave_path:
        # Autosaver.enabled is False without a path, so a throttle on its own
        # checkpoints nothing at all: refuse it instead of dropping it.
        refuse_unhonoured(
            args,
            ("autosave_interval", "autosave_seconds"),
            mode="without --autosave",
            hint="A checkpoint throttle needs a destination; pass --autosave PATH.",
        )
    interval = getattr(args, "autosave_interval", 0) or 0
    seconds = getattr(args, "autosave_seconds", 0.0) or 0.0
    if autosave_path and not interval and not seconds:
        interval = 1
    wrapped = OpentineHarness(
        _harness_from_args(args),
        autosave_path=autosave_path,
        autosave_steps=interval,
        autosave_seconds=seconds,
    )
    output = Path(args.save) if args.save else None
    try:
        run = wrapped.run_sync(task, context={"cwd": args.cwd}, save_path=output)
    except Exception as exc:
        run = wrapped.run
        if run is not None:
            output = output or (_runs_dir() / f"{run.id}.tine")
            run.save(output)
            _print_run_tree(run)
        console.print(f"[red]Harness failed:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    output = output or (_runs_dir() / f"{run.id}.tine")
    run.save(output)
    console.print(f"\n[{BRAND}]Saved:[/] {_terminal(output)}")
    _print_run_tree(run)


def cmd_show(args: argparse.Namespace) -> None:
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {_terminal(args.run_id)}[/]")
        raise SystemExit(1)
    _print_run_tree(Run.load(path))


def cmd_cost(args: argparse.Namespace) -> None:
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {_terminal(args.run_id)}[/]")
        raise SystemExit(1)
    run = Run.load(path)
    breakdown = run.cost_breakdown()
    console.print(
        f"[{BRAND}]# Cost[/] {_terminal(short_id(run.id))} "
        f"total={_cost_str(breakdown.total_cost)} "
        f"tokens={breakdown.total_tokens} "
        f"(in {breakdown.input_tokens} / out {breakdown.output_tokens})"
    )
    for title, values in (("By model", breakdown.by_model), ("By step kind", breakdown.by_kind)):
        if not values:
            continue
        table = Table(title=title, border_style=BRAND_DIM)
        table.add_column(title.removeprefix("By ").title())
        table.add_column("Cost", justify="right")
        for name, cost in sorted(values.items(), key=lambda item: item[1], reverse=True):
            table.add_row(_terminal(name or "-"), _cost_str(cost))
        console.print(table)
    if run.budget():
        console.print(f"[{BRAND_DIM}]Budget:[/] {_budget_str(run.budget())}")
    state = run.metadata.get("budget_state")
    if isinstance(state, dict) and state.get("breached"):
        console.print(
            f"[red]Over budget:[/] {_terminal(state.get('dimension'))} "
            f"{_terminal(state.get('incurred'))} > {_terminal(state.get('limit'))}"
        )
        raise SystemExit(1)
