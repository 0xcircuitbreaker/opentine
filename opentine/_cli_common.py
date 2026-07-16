"""Shared CLI state, run lookup, harness construction, and compact labels."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.text import Text

from opentine.core import Run, StepKind, short_id
from opentine.harnesses import (
    ClaudeCodeHarness,
    CodexCLIHarness,
    CursorHarness,
    GenericHarness,
    HermesHarness,
    KimiCodeHarness,
    OpenClawHarness,
    OpenCodeHarness,
    PiHarness,
)
from opentine.index import RunIndex

if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

BRAND = "#FF6900"
BRAND_DIM = "#CC5500"
STEP_ICONS = {
    StepKind.think: ("[bold bright_yellow]*[/]", "bright_yellow"),
    StepKind.tool: (f"[bold {BRAND}]>[/]", BRAND),
    StepKind.model: ("[bold cyan]#[/]", "cyan"),
    StepKind.done: ("[bold green]+[/]", "green"),
    StepKind.error: ("[bold red]x[/]", "red"),
}
# Auto-detect the terminal: colorize for interactive TTYs, but emit clean output when
# piped/redirected/captured (and honor NO_COLOR) so machine-readable JSON is not corrupted.
console = Console()
RUNS_DIR = Path(".tine_runs")
HARNESS_FACTORIES = {
    "claude-code": ClaudeCodeHarness,
    "codex": CodexCLIHarness,
    "cursor": CursorHarness,
    "generic": GenericHarness,
    "hermes": HermesHarness,
    "kimi-code": KimiCodeHarness,
    "openclaw": OpenClawHarness,
    "opencode": OpenCodeHarness,
    "pi": PiHarness,
}


def _runs_dir() -> Path:
    RUNS_DIR.mkdir(exist_ok=True)
    return RUNS_DIR


def _find_run(run_id: str) -> Path | None:
    direct = Path(run_id)
    if direct.exists():
        return direct
    for file in _runs_dir().glob("*.tine"):
        if file.stem.startswith(run_id):
            return file
    entry = RunIndex.open(_runs_dir()).lookup(run_id)
    if entry and (_runs_dir() / entry.file).exists():
        return _runs_dir() / entry.file
    return None


def _index_update(path: str | Path | None) -> None:
    if not path:
        return
    try:
        RunIndex.open(_runs_dir()).update_from_file(path)
    except Exception:
        pass


def _harness_from_args(args: argparse.Namespace):
    factory = HARNESS_FACTORIES[args.harness]
    command = shlex.split(args.harness_command) if args.harness_command else None
    if args.harness in {"generic", "pi"} and not command:
        raise SystemExit(f"--harness-command is required for {args.harness}")
    return factory(
        command=command,
        extra_args=args.harness_arg or (),
        cwd=args.cwd,
        login_env=args.harness_login_env,
        env_allowlist=args.harness_env or (),
        timeout_seconds=args.harness_timeout,
        max_output_chars=args.harness_max_output,
        max_events=args.harness_max_events,
        max_line_bytes=args.harness_max_line_bytes,
    )


def _resolve_step_ref(run: Run, ref: str | None) -> str:
    if ref is None:
        if not run.steps:
            raise ValueError("Run has no steps")
        return run.steps[-1].id
    if ref.isdigit():
        index = int(ref)
        if index < 0 or index >= len(run.steps):
            raise ValueError(f"Step index {index} out of range (0-{len(run.steps) - 1})")
        return run.steps[index].id
    return run.graph.resolve(ref)


def _run_context(run: Run, from_step: str | None = None) -> dict:
    steps = run.steps
    if from_step is not None:
        keep = run.graph.descendant_closure(run.graph.resolve(from_step))
        steps = [step for step in steps if step.id in keep]
    return {
        "from_step": from_step,
        "source_run": run.id,
        "steps": [
            {
                "id": step.id,
                "inputs": step.inputs,
                "kind": step.kind.value,
                "outputs": step.outputs,
                "short_id": short_id(step.id),
            }
            for step in steps
        ],
    }


def _display_value(value) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True)
    except TypeError:
        return repr(value)


def _step_label(step) -> Text:
    icon, _ = STEP_ICONS.get(step.kind, ("o", "white"))
    text, name, arguments = (
        step.inputs.get("text", ""),
        step.inputs.get("name", ""),
        step.inputs.get("arguments", {}),
    )
    if step.kind == StepKind.tool:
        if isinstance(arguments, dict):
            rendered = ", ".join(
                f"{escape(str(key))}={escape(_display_value(value))}"
                for key, value in arguments.items()
            )
        else:
            rendered = escape(_display_value(arguments))
        label = (
            f"{icon} [dim]{step.short_id}[/] [bold]tool[/]  "
            f"{escape(_display_value(name))}({rendered})"
        )
    elif text:
        preview = _display_value(text)[:80].replace("\n", " ")
        label = f'{icon} [dim]{step.short_id}[/] [bold]{step.kind.value}[/]  "{escape(preview)}"'
    else:
        label = f"{icon} [dim]{step.short_id}[/] [bold]{step.kind.value}[/]"
    return Text.from_markup(label)


def _cost_str(cost: float) -> str:
    return f"${cost:.4f}" if cost < 0.01 else f"${cost:.3f}"
