"""CLI for opentine — the demo IS the interface."""

from __future__ import annotations

import argparse
import importlib
import os
import shlex
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from opentine.core import Run, StepKind
from opentine.harnesses import ClaudeCodeHarness, CodexCLIHarness, CursorHarness, OpentineHarness

# Force UTF-8 on Windows
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Blaze Orange palette — Pantone 1505 C (#FF6900)
BRAND = "#FF6900"
BRAND_DIM = "#CC5500"
STEP_ICONS = {
    StepKind.think: ("[bold bright_yellow]*[/]", "bright_yellow"),
    StepKind.tool: (f"[bold {BRAND}]>[/]", BRAND),
    StepKind.model: ("[bold cyan]#[/]", "cyan"),
    StepKind.done: ("[bold green]+[/]", "green"),
    StepKind.error: ("[bold red]x[/]", "red"),
}

console = Console(force_terminal=True)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RUNS_DIR = Path(".tine_runs")
HARNESS_FACTORIES = {
    "claude-code": ClaudeCodeHarness,
    "codex": CodexCLIHarness,
    "cursor": CursorHarness,
}


def _runs_dir() -> Path:
    RUNS_DIR.mkdir(exist_ok=True)
    return RUNS_DIR


def _find_run(run_id: str) -> Path | None:
    """Find a run file by ID prefix or exact path."""
    p = Path(run_id)
    if p.exists():
        return p
    for f in _runs_dir().glob("*.tine"):
        if f.stem.startswith(run_id):
            return f
    return None


def _harness_from_args(args: argparse.Namespace):
    factory = HARNESS_FACTORIES[args.harness]
    command = shlex.split(args.harness_command) if args.harness_command else None
    return factory(
        command=command,
        extra_args=args.harness_arg or (),
        cwd=args.cwd,
    )


def _run_context(run: Run, from_step: int | None = None) -> dict:
    steps = run.steps[from_step:] if from_step is not None else run.steps
    return {
        "source_run": run.id,
        "from_step": from_step,
        "steps": [
            {
                "id": step.id,
                "kind": step.kind.value,
                "inputs": step.inputs,
                "outputs": step.outputs,
            }
            for step in steps
        ],
    }


def _step_label(step) -> Text:
    icon, color = STEP_ICONS.get(step.kind, ("o", "white"))
    text = step.inputs.get("text", "")
    name = step.inputs.get("name", "")
    args = step.inputs.get("arguments", {})
    if step.kind == StepKind.tool:
        args_str = ", ".join(
            f'{k}="{v}"' if isinstance(v, str) else f"{k}={v}" for k, v in args.items()
        )
        label = f"{icon} [bold]tool[/]  {name}({args_str})"
    elif text:
        preview = text[:80].replace("\n", " ")
        if len(text) > 80:
            preview += "..."
        label = f'{icon} [bold]{step.kind.value}[/]  "{preview}"'
    else:
        label = f"{icon} [bold]{step.kind.value}[/]  {step.id}"
    return Text.from_markup(label)


def _cost_str(cost: float) -> str:
    if cost < 0.01:
        return f"${cost:.4f}"
    return f"${cost:.3f}"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace) -> None:
    """Execute a script that returns a Run, stream steps, save."""
    if args.harness:
        cmd_run_harness(args)
        return

    if not args.script:
        console.print("[red]Provide a Python script or use --harness with --prompt.[/]")
        sys.exit(1)

    script = Path(args.script)
    if not script.exists():
        console.print(f"[red]File not found: {script}[/]")
        sys.exit(1)

    console.print(f"[{BRAND}]# Running {script.name}...[/]\n")

    # Execute the script — it should produce a Run
    spec = importlib.util.spec_from_file_location("__tine_script__", str(script))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["__tine_script__"] = mod
    spec.loader.exec_module(mod)

    # Look for a Run object in the module
    run = None
    for name in dir(mod):
        obj = getattr(mod, name)
        if isinstance(obj, Run):
            run = obj
            break

    if run is None:
        console.print(
            "[red]No Run object found in script."
            " Assign the result of agent.run() or agent.run_sync().[/]"
        )
        sys.exit(1)

    # Save
    out_path = _runs_dir() / f"{run.id}.tine"
    run.save(out_path)
    console.print(f"\n[{BRAND}]Saved:[/] {out_path}")
    _print_run_tree(run)


def cmd_run_harness(args: argparse.Namespace) -> None:
    """Execute an external harness and save its run tree."""
    task = args.prompt or args.script
    if not task:
        console.print("[red]--prompt is required when running a harness.[/]")
        sys.exit(1)

    harness = _harness_from_args(args)
    wrapped = OpentineHarness(harness)
    console.print(f"[{BRAND}]# Running {args.harness} harness...[/]\n")

    out_path = Path(args.save) if args.save else None
    try:
        run = wrapped.run_sync(task, context={"cwd": args.cwd}, save_path=out_path)
    except Exception as exc:
        run = wrapped.run
        if run is not None:
            out_path = out_path or (_runs_dir() / f"{run.id}.tine")
            run.save(out_path)
            console.print(f"\n[yellow]Saved failed run:[/] {out_path}")
            _print_run_tree(run)
        console.print(f"[red]Harness failed:[/] {exc}")
        sys.exit(1)

    out_path = out_path or (_runs_dir() / f"{run.id}.tine")
    run.save(out_path)
    console.print(f"\n[{BRAND}]Saved:[/] {out_path}")
    _print_run_tree(run)


def cmd_show(args: argparse.Namespace) -> None:
    """Pretty-print a run tree."""
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {args.run_id}[/]")
        sys.exit(1)
    run = Run.load(path)
    _print_run_tree(run)


def _print_run_tree(run: Run) -> None:
    """Render the run tree like git log --graph."""
    status_color = {"completed": "green", "failed": "red", "paused": "yellow", "running": "cyan"}
    sc = status_color.get(run.status.value, "white")

    header = (
        f"[bold {BRAND}]#[/] [bold]{run.id}[/]  "
        f"model=[dim]{run.model_info}[/]  "
        f"steps=[dim]{len(run.steps)}[/]  "
        f"cost=[dim]{_cost_str(run.total_cost)}[/]  "
        f"[{sc}]{run.status.value}[/]"
    )
    tree = Tree(Text.from_markup(header))

    for step in run.steps:
        label = _step_label(step)
        cost_info = f"  [dim]{_cost_str(step.cost)}[/]" if step.cost > 0 else ""
        dur_info = f"  [dim]{step.duration:.1f}s[/]" if step.duration > 0 else ""
        node_text = Text.from_markup(str(label) + cost_info + dur_info)
        tree.add(node_text)

    console.print()
    console.print(tree)
    console.print()

    if run.metadata.get("forked_from"):
        console.print(
            f"  [{BRAND_DIM}]Forked from:[/] {run.metadata['forked_from']} "
            f"at step {run.metadata.get('fork_point', '?')}"
        )
        console.print()


def cmd_ls(args: argparse.Namespace) -> None:
    """List recent runs."""
    runs_dir = _runs_dir()
    files = sorted(runs_dir.glob("*.tine"), key=lambda f: f.stat().st_mtime, reverse=True)

    if not files:
        console.print(
            "[dim]No runs found. Use[/] [bold]tine run <script.py>[/] [dim]to create one.[/]"
        )
        return

    table = Table(title=f"[{BRAND}]Recent Runs[/]", border_style=BRAND_DIM)
    table.add_column("ID", style="bold")
    table.add_column("Status")
    table.add_column("Model", style="dim")
    table.add_column("Steps", justify="right")
    table.add_column("Cost", justify="right")
    table.add_column("File", style="dim")

    for f in files[:20]:
        try:
            run = Run.load(f)
            sc = {"completed": "green", "failed": "red", "paused": "yellow", "running": "cyan"}
            status = f"[{sc.get(run.status.value, 'white')}]{run.status.value}[/]"
            table.add_row(
                run.id,
                status,
                run.model_info,
                str(len(run.steps)),
                _cost_str(run.total_cost),
                f.name,
            )
        except Exception:
            table.add_row("?", "[red]corrupt[/]", "", "", "", f.name)

    console.print(table)


def cmd_fork(args: argparse.Namespace) -> None:
    """Fork a run from a specific step."""
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {args.run_id}[/]")
        sys.exit(1)
    run = Run.load(path)

    # Find the step to fork from
    step_idx = args.from_step
    if step_idx < 0 or step_idx >= len(run.steps):
        console.print(f"[red]Step index {step_idx} out of range (0-{len(run.steps) - 1})[/]")
        sys.exit(1)

    fork_step = run.steps[step_idx]
    forked = run.fork(fork_step.id)

    out = args.save or str(_runs_dir() / f"{forked.id}.tine")
    if args.harness:
        forked.metadata["next_harness"] = args.harness
        if args.prompt:
            harness = _harness_from_args(args)
            wrapped = OpentineHarness(harness, run=forked)
            try:
                forked = wrapped.run_sync(
                    args.prompt,
                    context={
                        **_run_context(run, from_step=step_idx),
                        "forked_from": run.id,
                        "fork_point": fork_step.id,
                    },
                    save_path=out,
                )
            except Exception as exc:
                forked.save(out)
                console.print(f"[red]Harness failed after fork:[/] {exc}")
                sys.exit(1)

    forked.save(out)
    console.print(f"[{BRAND}]# Forked[/] {run.id} -> {forked.id} from step {step_idx}")
    if args.harness:
        console.print(f"[dim]Harness: {args.harness}[/]")
    console.print(f"[dim]Saved: {out}[/]")
    _print_run_tree(forked)


def cmd_replay(args: argparse.Namespace) -> None:
    """Replay a run from a specific step."""
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {args.run_id}[/]")
        sys.exit(1)
    run = Run.load(path)

    if args.harness:
        task = args.prompt or run.user_prompt
        if not task:
            console.print("[red]--prompt is required when replaying a harness run.[/]")
            sys.exit(1)
        if args.from_step is not None and (args.from_step < 0 or args.from_step >= len(run.steps)):
            console.print("[red]Step index out of range[/]")
            sys.exit(1)

        harness = _harness_from_args(args)
        wrapped = OpentineHarness(harness)
        out = Path(args.save) if args.save else None
        try:
            replayed = wrapped.run_sync(
                task,
                context=_run_context(run, args.from_step),
                save_path=out,
            )
        except Exception as exc:
            replayed = wrapped.run
            if replayed is not None:
                out = out or (_runs_dir() / f"{replayed.id}.tine")
                replayed.save(out)
            console.print(f"[red]Harness replay failed:[/] {exc}")
            sys.exit(1)

        out = out or (_runs_dir() / f"{replayed.id}.tine")
        replayed.save(out)
        console.print(f"[{BRAND}]# Replayed[/] {run.id} with {args.harness}")
        console.print(f"[dim]Saved: {out}[/]")
        _print_run_tree(replayed)
        if args.compare:
            _print_diff_table(run, replayed)
        return

    if args.from_step is not None:
        if args.from_step < 0 or args.from_step >= len(run.steps):
            console.print("[red]Step index out of range[/]")
            sys.exit(1)
        console.print(f"[{BRAND}]Replaying from step {args.from_step}...[/]\n")
        for step in run.steps[args.from_step :]:
            label = _step_label(step)
            console.print(f"  {label}")
    else:
        console.print(f"[{BRAND}]Replaying full run...[/]\n")
        for step in run.steps:
            label = _step_label(step)
            console.print(f"  {label}")


def cmd_diff(args: argparse.Namespace) -> None:
    """Diff two runs step-by-step."""
    path_a = _find_run(args.run_a)
    path_b = _find_run(args.run_b)
    if not path_a:
        console.print(f"[red]Run not found: {args.run_a}[/]")
        sys.exit(1)
    if not path_b:
        console.print(f"[red]Run not found: {args.run_b}[/]")
        sys.exit(1)

    run_a = Run.load(path_a)
    run_b = Run.load(path_b)
    _print_diff_table(run_a, run_b)


def _print_diff_table(run_a: Run, run_b: Run) -> None:
    table = Table(title=f"[{BRAND}]Diff: {run_a.id} vs {run_b.id}[/]", border_style=BRAND_DIM)
    table.add_column("#", justify="right", style="dim")
    table.add_column(f"{run_a.id}", style="cyan")
    table.add_column(f"{run_b.id}", style="bright_yellow")
    table.add_column("Match")

    max_steps = max(len(run_a.steps), len(run_b.steps))
    for i in range(max_steps):
        sa = run_a.steps[i] if i < len(run_a.steps) else None
        sb = run_b.steps[i] if i < len(run_b.steps) else None
        la = str(_step_label(sa)) if sa else "[dim]---[/]"
        lb = str(_step_label(sb)) if sb else "[dim]---[/]"
        match = "[green]=[/]" if (sa and sb and sa.id == sb.id) else f"[{BRAND}]![/]"
        table.add_row(str(i), la, lb, match)

    console.print(table)


def cmd_resume(args: argparse.Namespace) -> None:
    """Resume a paused run."""
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {args.run_id}[/]")
        sys.exit(1)

    run = Run.resume(path)
    console.print(f"[{BRAND}]# Resumed[/] {run.id} ({len(run.steps)} steps loaded)")
    _print_run_tree(run)
    run.save(path)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tine", description="opentine — git for agent runs")
    sub = parser.add_subparsers(dest="command")

    p_run = sub.add_parser("run", help="Execute a script and save the run tree")
    p_run.add_argument(
        "script",
        nargs="?",
        help="Python script to execute, or prompt for --harness",
    )
    _add_harness_args(p_run)
    p_run.add_argument("--save", help="Output path for harness run")

    p_show = sub.add_parser("show", help="Pretty-print a run tree")
    p_show.add_argument("run_id", help="Run ID or .tine file path")

    sub.add_parser("ls", help="List recent runs")

    p_fork = sub.add_parser("fork", help="Fork a run from a specific step")
    p_fork.add_argument("run_id", help="Run ID or .tine file path")
    p_fork.add_argument("--from-step", type=int, required=True, help="Step index to fork from")
    p_fork.add_argument("--save", help="Output path for forked run")
    _add_harness_args(p_fork)

    p_replay = sub.add_parser("replay", help="Replay a run")
    p_replay.add_argument("run_id", help="Run ID or .tine file path")
    p_replay.add_argument("--from-step", type=int, default=None, help="Step index to replay from")
    p_replay.add_argument("--save", help="Output path for replayed harness run")
    p_replay.add_argument(
        "--compare",
        action="store_true",
        help="Diff the original and replayed runs",
    )
    _add_harness_args(p_replay)

    p_diff = sub.add_parser("diff", help="Diff two runs")
    p_diff.add_argument("run_a", help="First run ID or path")
    p_diff.add_argument("run_b", help="Second run ID or path")

    p_resume = sub.add_parser("resume", help="Resume a paused run")
    p_resume.add_argument("run_id", help="Run ID or .tine file path")

    return parser


def _add_harness_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--harness",
        choices=sorted(HARNESS_FACTORIES),
        help="External agent harness to run through opentine",
    )
    parser.add_argument("--prompt", help="Task prompt for the selected harness")
    parser.add_argument("--cwd", help="Working directory for harness command")
    parser.add_argument(
        "--harness-command",
        help='Override harness command, e.g. "claude -p" or "codex exec"',
    )
    parser.add_argument(
        "--harness-arg",
        action="append",
        default=[],
        help="Extra argument passed to the harness command; repeat as needed",
    )


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    commands = {
        "run": cmd_run,
        "show": cmd_show,
        "ls": cmd_ls,
        "fork": cmd_fork,
        "replay": cmd_replay,
        "diff": cmd_diff,
        "resume": cmd_resume,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        console.print(f"\n  [{BRAND}]opentine[/] — git for agent runs\n")
        parser.print_help()


if __name__ == "__main__":
    main()
