"""CLI for opentine — the demo IS the interface."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import shlex
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from opentine._canon import FORMAT_VERSION, _integrity_digest
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
    OpentineHarness,
    PiHarness,
)
from opentine.index import IndexEntry, Query, QueryError, RunIndex, _parse_date, match_entry

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
    """Find a run file by path, filename-stem prefix, or indexed run-id."""
    p = Path(run_id)
    if p.exists():
        return p
    for f in _runs_dir().glob("*.tine"):
        if f.stem.startswith(run_id):
            return f
    # Fall back to the index for runs saved under a custom filename.
    entry = RunIndex.open(_runs_dir()).lookup(run_id)
    if entry:
        candidate = _runs_dir() / entry.file
        if candidate.exists():
            return candidate
    return None


def _index_update(path: str | Path | None) -> None:
    """Best-effort: refresh the index entry for a freshly written run file."""
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
    )


def _resolve_step_ref(run: Run, ref: str | None) -> str:
    if ref is None:
        if not run.steps:
            raise ValueError("Run has no steps")
        return run.steps[-1].id
    if ref.isdigit():
        idx = int(ref)
        if idx < 0 or idx >= len(run.steps):
            raise ValueError(f"Step index {idx} out of range (0-{len(run.steps) - 1})")
        return run.steps[idx].id
    return run.graph.resolve(ref)


def _run_context(run: Run, from_step: str | None = None) -> dict:
    if from_step is None:
        steps = run.steps
    else:
        start = run.graph.resolve(from_step)
        keep = run.graph.descendant_closure(start)
        steps = [step for step in run.steps if step.id in keep]
    return {
        "source_run": run.id,
        "from_step": from_step,
        "steps": [
            {
                "id": step.id,
                "short_id": short_id(step.id),
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
        if isinstance(args, dict):
            args_str = ", ".join(
                f'{escape(str(k))}="{escape(v)}"'
                if isinstance(v, str)
                else f"{escape(str(k))}={escape(_display_value(v))}"
                for k, v in args.items()
            )
        else:
            args_str = escape(_display_value(args))
        label = (
            f"{icon} [dim]{step.short_id}[/] [bold]tool[/]  "
            f"{escape(_display_value(name))}({args_str})"
        )
    elif text:
        rendered_text = _display_value(text)
        preview = rendered_text[:80].replace("\n", " ")
        if len(rendered_text) > 80:
            preview += "..."
        label = f'{icon} [dim]{step.short_id}[/] [bold]{step.kind.value}[/]  "{escape(preview)}"'
    else:
        label = f"{icon} [dim]{step.short_id}[/] [bold]{step.kind.value}[/]"
    return Text.from_markup(label)


def _display_value(value) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True)
    except TypeError:
        return repr(value)


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
    autosave_path = getattr(args, "autosave", None)
    interval = getattr(args, "autosave_interval", 0) or 0
    seconds = getattr(args, "autosave_seconds", 0.0) or 0.0
    if autosave_path and not interval and not seconds:
        interval = 1  # `--autosave PATH` alone -> checkpoint every step
    wrapped = OpentineHarness(
        harness,
        autosave_path=autosave_path,
        autosave_steps=interval,
        autosave_seconds=seconds,
    )
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


def cmd_verify(args: argparse.Namespace) -> None:
    """Verify a .tine artifact integrity digest."""
    path = _find_run(args.run_id)
    if not path:
        result = Run.verify_integrity(args.run_id)
        console.print(
            f"[red]FAILED[/] {escape(args.run_id)}: {escape(result.reason)}",
            highlight=False,
        )
        sys.exit(1)

    result = Run.verify_integrity(path)
    if not result.ok:
        console.print(
            f"[red]FAILED[/] {escape(str(path))}: {escape(result.reason)}", highlight=False
        )
        if result.expected:
            console.print(f"[dim]expected:[/] {escape(result.expected)}", highlight=False)
        if result.actual:
            console.print(f"[dim]actual:[/]   {escape(result.actual)}", highlight=False)
        sys.exit(1)

    digest = result.actual or result.expected or ""
    draft = " [yellow](draft / autosave checkpoint)[/]" if result.draft else ""
    console.print(f"[green]OK[/] {escape(str(path))} sha256:{digest[:12]}{draft}", highlight=False)
    _verify_signature_if_requested(args, path)


def _verify_signature_if_requested(args: argparse.Namespace, path: Path) -> None:
    """Fail-closed signature check: supplying any key implies --require-signature."""
    from opentine.signing import (
        SignatureError,
        ed25519_public_from_file,
        hmac_key_from_env,
        hmac_key_from_file,
    )

    key_env = getattr(args, "key_env", None)
    key_file = getattr(args, "key_file", None)
    pubkey = getattr(args, "pubkey", None)
    require = bool(key_env or key_file or pubkey or getattr(args, "require_signature", False))
    if not require:
        return
    try:
        hmac_key = None
        if key_env:
            hmac_key = hmac_key_from_env(key_env)
        elif key_file:
            hmac_key = hmac_key_from_file(key_file)
        public_key = ed25519_public_from_file(pubkey) if pubkey else None
    except SignatureError as exc:
        console.print(f"[red]SIGNATURE FAILED[/] {escape(str(exc))}", highlight=False)
        sys.exit(1)

    sig = Run.verify_signature(
        path,
        hmac_key=hmac_key,
        public_key=public_key,
        trust_embedded=getattr(args, "trust_embedded_key", False),
    )
    if sig.ok:
        tofu = " [yellow](TOFU — self-asserted key, not verified)[/]" if "tofu" in sig.state else ""
        console.print(
            f"[green]SIGNATURE OK[/] alg={sig.algorithm} key_id={sig.key_id or '-'} "
            f"signer={escape(str(sig.signer or '-'))}{tofu}",
            highlight=False,
        )
        return
    console.print(
        f"[red]SIGNATURE FAILED[/] state={sig.state}: {escape(sig.reason)}", highlight=False
    )
    sys.exit(1)


def cmd_sign(args: argparse.Namespace) -> None:
    """Sign a .tine artifact (HMAC-SHA256 by default, Ed25519 optional)."""
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {args.run_id}[/]")
        sys.exit(1)
    from opentine.signing import (
        SignatureError,
        ed25519_private_from_file,
        hmac_key_from_env,
        hmac_key_from_file,
    )

    integ = Run.verify_integrity(path)
    if not integ.ok and not args.force:
        console.print(
            f"[red]Refusing to sign: integrity check failed "
            f"({escape(integ.reason)}). Pass --force to override.[/]",
            highlight=False,
        )
        sys.exit(1)

    run = Run.load(path)
    algo = args.algorithm
    try:
        if algo == "ed25519":
            if not args.ed25519_key_file:
                console.print("[red]--ed25519-key-file is required for ed25519 signing.[/]")
                sys.exit(1)
            key = ed25519_private_from_file(args.ed25519_key_file)
        elif args.key_env:
            key = hmac_key_from_env(args.key_env)
        elif args.key_file:
            key = hmac_key_from_file(args.key_file)
        else:
            console.print("[red]Provide --key-env NAME or --key-file PATH for HMAC signing.[/]")
            sys.exit(1)
        out = Path(args.save) if args.save else path
        run.save(
            out,
            sign_key=key,
            sign_algorithm=algo,
            key_id=args.key_id,
            signer=args.signer,
        )
    except SignatureError as exc:
        console.print(f"[red]Signing failed:[/] {escape(str(exc))}", highlight=False)
        sys.exit(1)

    console.print(f"[{BRAND}]# Signed[/] {short_id(run.id)} alg={algo} key_id={args.key_id or '-'}")
    console.print(f"[dim]Saved:[/] {escape(str(out))}", highlight=False)


def cmd_keygen(args: argparse.Namespace) -> None:
    """Generate an Ed25519 keypair for signing."""
    from opentine._canon import atomic_write_text
    from opentine.signing import SignatureError, generate_ed25519

    try:
        seed, pub = generate_ed25519()
    except SignatureError as exc:
        console.print(f"[red]{escape(str(exc))}[/]", highlight=False)
        sys.exit(1)

    if args.out:
        atomic_write_text(args.out, seed + "\n")
        try:
            os.chmod(args.out, 0o600)
        except OSError:
            pass
        console.print(f"[dim]private key (ed25519 seed) ->[/] {escape(args.out)}", highlight=False)
    else:
        console.print(f"private (seed hex): {seed}")

    pub_target = args.pub or (args.out + ".pub" if args.out else None)
    if pub_target:
        atomic_write_text(pub_target, pub + "\n")
        console.print(f"[dim]public key ->[/] {escape(pub_target)}", highlight=False)
    else:
        console.print(f"public (hex): {pub}")


def cmd_migrate(args: argparse.Namespace) -> None:
    """Upgrade a .tine artifact to the current format version."""
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {args.run_id}[/]")
        sys.exit(1)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        msg = f"[red]Cannot read {escape(str(path))}: {escape(str(exc))}[/]"
        console.print(msg, highlight=False)
        sys.exit(1)

    src_version = raw.get("format_version", "missing")
    target = args.to if args.to is not None else FORMAT_VERSION
    if target != FORMAT_VERSION:
        console.print(f"[red]This build only migrates to the current format v{FORMAT_VERSION}.[/]")
        sys.exit(1)

    # Migration is not a trust boundary: verify the source first so a tampered
    # artifact is not silently "laundered" into a fresh valid digest.
    src_result = Run.verify_integrity(path)
    if not src_result.ok and not args.force:
        console.print(
            f"[red]Refusing to migrate: source integrity check failed "
            f"({escape(src_result.reason)}). Pass --force to migrate anyway.[/]",
            highlight=False,
        )
        sys.exit(1)

    try:
        run = Run.load(path)  # auto-migrates in memory; raises on unknown/future versions
    except ValueError as exc:
        console.print(f"[red]Migration failed:[/] {escape(str(exc))}", highlight=False)
        sys.exit(1)

    if src_version == run.format_version:
        console.print(
            f"[dim]{path.name} is already at format v{run.format_version}; nothing to do.[/]"
        )
        return

    preview = run.to_dict(redact=True)
    preview["metadata"]["integrity"] = {"algorithm": "sha256", "digest": _integrity_digest(preview)}
    new_digest = preview["metadata"]["integrity"]["digest"]
    old_digest = ((raw.get("metadata") or {}).get("integrity") or {}).get("digest", "")
    sig_dropped = bool(((raw.get("metadata") or {}).get("integrity") or {}).get("signature"))

    if args.dry_run or (not args.in_place and not args.save):
        console.print(f"[{BRAND}]# Migration preview[/] {escape(path.name)}", highlight=False)
        console.print(f"  format_version: {src_version} -> {run.format_version}")
        console.print(f"  digest: {old_digest[:12] or '-'} -> {new_digest[:12]}")
        if sig_dropped:
            console.print("  [yellow]signature dropped — re-sign after migrating[/]")
        console.print("[dim]Dry run — no file written. Use --in-place or --save PATH to apply.[/]")
        return

    out = path if args.in_place else Path(args.save)
    if not args.in_place and out.exists() and not args.force:
        console.print(f"[red]Refusing to overwrite existing file: {out}. Pass --force.[/]")
        sys.exit(1)
    run.save(out)
    result = Run.verify_integrity(out)
    badge = "[green]OK[/]" if result.ok else "[red]FAILED[/]"
    console.print(
        f"[{BRAND}]# Migrated[/] {escape(path.name)} v{src_version} -> v{run.format_version}",
        highlight=False,
    )
    console.print(f"[dim]Saved:[/] {escape(str(out))} {badge}", highlight=False)
    if sig_dropped:
        console.print("[yellow]Signature was dropped by migration — re-sign if needed.[/]")


def _budget_str(budget) -> str:
    parts = []
    if budget.max_cost is not None:
        parts.append(f"cost<=${budget.max_cost}")
    if budget.max_usage is not None:
        parts.append(f"tokens<={budget.max_usage}")
    if budget.max_steps is not None:
        parts.append(f"steps<={budget.max_steps}")
    if budget.max_duration is not None:
        parts.append(f"duration<={budget.max_duration}s")
    parts.append(f"on_breach={budget.on_breach}")
    return ", ".join(parts)


def cmd_cost(args: argparse.Namespace) -> None:
    """Show a cost/usage breakdown and budget state for a run."""
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {args.run_id}[/]")
        sys.exit(1)
    run = Run.load(path)
    bd = run.cost_breakdown()
    console.print(
        f"[{BRAND}]# Cost[/] {short_id(run.id)}  total={_cost_str(bd.total_cost)}  "
        f"tokens={bd.total_tokens} (in {bd.input_tokens} / out {bd.output_tokens})"
    )

    if bd.by_model:
        table = Table(title="By model", border_style=BRAND_DIM)
        table.add_column("Model")
        table.add_column("Cost", justify="right")
        for model, cost in sorted(bd.by_model.items(), key=lambda kv: kv[1], reverse=True):
            table.add_row(escape(model or "-"), _cost_str(cost))
        console.print(table)
    if len(bd.by_kind) > 1:
        table = Table(title="By step kind", border_style=BRAND_DIM)
        table.add_column("Kind")
        table.add_column("Cost", justify="right")
        for kind, cost in sorted(bd.by_kind.items(), key=lambda kv: kv[1], reverse=True):
            table.add_row(kind, _cost_str(cost))
        console.print(table)

    budget = run.budget()
    if budget:
        console.print(f"[{BRAND_DIM}]Budget:[/] {_budget_str(budget)}")
    state = run.metadata.get("budget_state")
    if isinstance(state, dict) and state.get("breached"):
        console.print(
            f"[red]Over budget:[/] {escape(str(state.get('dimension')))} "
            f"{state.get('incurred')} > {state.get('limit')}",
            highlight=False,
        )
        sys.exit(1)


def _print_run_tree(run: Run) -> None:
    """Render the run tree like git log --graph."""
    status_color = {"completed": "green", "failed": "red", "paused": "yellow", "running": "cyan"}
    sc = status_color.get(run.status.value, "white")

    header = (
        f"[bold {BRAND}]#[/] [bold]{short_id(run.id)}[/]  "
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

    budget = run.budget()
    if budget:
        console.print(f"  [{BRAND_DIM}]budget:[/] {_budget_str(budget)}")
    state = run.metadata.get("budget_state")
    if isinstance(state, dict) and state.get("breached"):
        console.print(
            f"  [red]over budget:[/] {escape(str(state.get('dimension')))} "
            f"{state.get('incurred')} > {state.get('limit')}",
            highlight=False,
        )


STATUS_COLORS = {"completed": "green", "failed": "red", "paused": "yellow", "running": "cyan"}


def _has_filters(query: Query) -> bool:
    return bool(
        query.text
        or query.tags
        or query.model
        or query.status
        or query.cost_min is not None
        or query.cost_max is not None
        or query.after is not None
        or query.before is not None
    )


def _query_from_ls_args(args: argparse.Namespace) -> Query:
    query = Query()
    query.tags = [t.strip().lower() for t in (args.tag or []) if t.strip()]
    query.model = args.model.lower() if args.model else None
    query.status = args.status.lower() if args.status else None
    query.cost_min = args.cost_min
    query.cost_max = args.cost_max
    query.after = _parse_date(args.since) if args.since else None
    query.before = _parse_date(args.until) if args.until else None
    query.text = [g.lower() for g in (args.grep or [])]
    return query


def _entries_table(title: str, entries: list[IndexEntry], *, show_unreadable: bool) -> Table:
    table = Table(title=f"[{BRAND}]{title}[/]", border_style=BRAND_DIM)
    table.add_column("ID", style="bold")
    table.add_column("Status")
    table.add_column("Model", style="dim")
    table.add_column("Steps", justify="right")
    table.add_column("Cost", justify="right")
    table.add_column("Tags", style=BRAND_DIM)
    table.add_column("File", style="dim")
    for entry in entries:
        if entry.unreadable:
            if show_unreadable:
                table.add_row("?", "[red]corrupt[/]", "", "", "", "", escape(entry.file))
            continue
        status = f"[{STATUS_COLORS.get(entry.status, 'white')}]{escape(entry.status)}[/]"
        table.add_row(
            short_id(entry.run_id),
            status,
            escape(entry.model),
            str(entry.steps),
            _cost_str(entry.cost),
            escape(", ".join(entry.tags)),
            escape(entry.file),
        )
    return table


def cmd_ls(args: argparse.Namespace) -> None:
    """List recent runs, optionally filtered by tag/model/status/cost/date/text."""
    index = RunIndex.open(_runs_dir()).sync()
    if not index.entries:
        console.print(
            "[dim]No runs found. Use[/] [bold]tine run <script.py>[/] [dim]to create one.[/]"
        )
        return

    query = _query_from_ls_args(args)
    filtering = _has_filters(query)
    readable = [e for e in index.entries.values() if not e.unreadable and match_entry(e, query)]
    readable.sort(key=lambda e: e.created_at, reverse=True)
    limit = args.limit or 20
    rows = readable[:limit]
    # Only surface corrupt files in an unfiltered listing.
    if not filtering:
        rows = rows + [e for e in index.entries.values() if e.unreadable]

    if filtering and not readable:
        console.print("[dim]No runs match the given filters.[/]")
        return
    console.print(_entries_table("Recent Runs", rows, show_unreadable=not filtering))


def cmd_search(args: argparse.Namespace) -> None:
    """Search runs with a small query DSL (tag:/model:/status:/cost:/after:/before: + free text)."""
    query_str = " ".join(args.query)
    index = RunIndex.open(_runs_dir())
    try:
        results = index.search(query_str)
    except QueryError as exc:
        console.print(f"[red]Bad query:[/] {escape(str(exc))}", highlight=False)
        sys.exit(1)
    if not results:
        console.print("[dim]No runs match.[/]")
        return
    console.print(_entries_table(f"Search: {query_str or '*'}", results, show_unreadable=False))


def cmd_reindex(args: argparse.Namespace) -> None:
    """Rebuild the run index from scratch."""
    index = RunIndex.open(_runs_dir()).reindex()
    total = len(index.entries)
    bad = sum(1 for e in index.entries.values() if e.unreadable)
    console.print(f"[{BRAND}]# Reindexed[/] {total} run(s), {bad} unreadable -> {index.path}")


def cmd_tag(args: argparse.Namespace) -> None:
    """Add, remove, or list tags on a run."""
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {args.run_id}[/]")
        sys.exit(1)
    run = Run.load(path)

    if args.list or (not args.add and not args.remove):
        if run.tags:
            console.print(", ".join(run.tags))
        else:
            console.print("[dim](no tags)[/]")
        return

    changed = False
    for tag in args.add or []:
        changed |= run.add_tag(tag)
    for tag in args.remove or []:
        changed |= run.remove_tag(tag)
    if changed:
        run.save(path)
        _index_update(path)
    tags_str = ", ".join(run.tags) if run.tags else "(none)"
    console.print(f"[{BRAND}]# Tags[/] {short_id(run.id)}: {tags_str}")


def cmd_fork(args: argparse.Namespace) -> None:
    """Fork a run from a specific step."""
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {args.run_id}[/]")
        sys.exit(1)
    run = Run.load(path)

    try:
        fork_step_id = _resolve_step_ref(run, args.from_step)
    except (KeyError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        sys.exit(1)
    fork_step = run.get_step(fork_step_id)
    assert fork_step is not None
    forked = run.fork(fork_step.id)

    out = args.save or str(_runs_dir() / f"{forked.id}.tine")
    if Path(out).exists() and not args.force:
        console.print(
            f"[red]Refusing to overwrite existing file: {out}. Pass --force to replace it.[/]"
        )
        sys.exit(1)
    if args.harness:
        forked.metadata["next_harness"] = args.harness
        if args.prompt:
            harness = _harness_from_args(args)
            wrapped = OpentineHarness(harness, run=forked)
            try:
                forked = wrapped.run_sync(
                    args.prompt,
                    context={
                        **_run_context(run, from_step=fork_step.id),
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
    console.print(
        f"[{BRAND}]# Forked[/] {short_id(run.id)} -> {short_id(forked.id)} "
        f"from {short_id(fork_step.id)}"
    )
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

    if args.inspect or args.dry_run:
        selected = run.steps
        if args.from_step is not None:
            try:
                start = _resolve_step_ref(run, args.from_step)
            except (KeyError, ValueError) as exc:
                console.print(f"[red]{exc}[/]")
                sys.exit(1)
            keep = run.graph.descendant_closure(start)
            selected = [step for step in run.steps if step.id in keep]
        console.print(f"[{BRAND}]Inspecting recorded steps...[/]\n")
        for step in selected:
            console.print(f"  {_step_label(step)}")
        return

    if args.harness:
        task = args.prompt or run.user_prompt
        if not task:
            console.print("[red]--prompt is required when replaying a harness run.[/]")
            sys.exit(1)
        try:
            start = _resolve_step_ref(run, args.from_step) if args.from_step is not None else None
        except (KeyError, ValueError) as exc:
            console.print(f"[red]{exc}[/]")
            sys.exit(1)

        harness = _harness_from_args(args)
        wrapped = OpentineHarness(harness)
        out = Path(args.save) if args.save else None
        try:
            replayed = wrapped.run_sync(
                task,
                context=_run_context(run, start),
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

    if args.mode == "rerun":
        console.print(
            "[red]Rerun replay requires an explicit --harness or opentine-native Agent API.[/]"
        )
        sys.exit(1)
    replayed = run.fork(_resolve_step_ref(run, args.from_step), new_run_id=f"{run.id}-replay")
    replayed.metadata["replay"] = {
        "mode": "cache",
        "source_run": run.id,
        "reused_steps": len(replayed.steps),
    }
    replayed.status = run.status
    out = Path(args.save) if args.save else _runs_dir() / f"{replayed.id}.tine"
    replayed.save(out)
    console.print(f"[{BRAND}]# Cached replay[/] reused {len(replayed.steps)} recorded steps")
    console.print(f"[dim]Saved: {out}[/]")


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
    table = Table(
        title=f"[{BRAND}]Diff: {short_id(run_a.id)} vs {short_id(run_b.id)}[/]",
        border_style=BRAND_DIM,
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column(f"{short_id(run_a.id)}", style="cyan")
    table.add_column(f"{short_id(run_b.id)}", style="bright_yellow")
    table.add_column("Match")

    diff = run_a.diff(run_b)
    common = short_id(diff.common_ancestor) if diff.common_ancestor else "-"
    marker = "[green]=[/]" if diff.common_ancestor else f"[{BRAND}]![/]"
    table.add_row("base", common, common, marker)
    for step in diff.only_a:
        table.add_row("", str(_step_label(step)), "[dim]---[/]", f"[{BRAND}]only A[/]")
    for step in diff.only_b:
        table.add_row("", "[dim]---[/]", str(_step_label(step)), f"[{BRAND}]only B[/]")
    for change in diff.changed:
        table.add_row(
            "",
            str(_step_label(change.step_a)),
            str(_step_label(change.step_b)),
            "[yellow]changed[/]",
        )
        for delta in change.fields:
            keys = f" [{', '.join(delta.changed_keys)}]" if delta.changed_keys else ""
            label = f"{escape(delta.name)}{escape(keys)}"
            before = escape(_display_value(delta.before))[:48]
            after = escape(_display_value(delta.after))[:48]
            table.add_row(
                "",
                f"[red]- {label}: {before}[/]",
                f"[green]+ {label}: {after}[/]",
                "",
            )

    console.print(table)


def cmd_resume(args: argparse.Namespace) -> None:
    """Resume a paused run."""
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {args.run_id}[/]")
        sys.exit(1)

    run = Run.load(path)
    if not run.manifest.get("resume", False):
        kind = run.manifest.get("kind", "unknown")
        console.print(
            f"[red]Run is not resumable: manifest kind={kind!r} does not declare resume support.[/]"
        )
        sys.exit(1)
    run = Run.resume(path)
    console.print(f"[{BRAND}]# Loaded resumable run[/] {short_id(run.id)} ({len(run.steps)} steps)")
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
    p_run.add_argument("--autosave", help="Stream crash-safe draft checkpoints to this path")
    p_run.add_argument(
        "--autosave-interval", type=int, default=0, metavar="N", help="Checkpoint every N steps"
    )
    p_run.add_argument(
        "--autosave-seconds",
        type=float,
        default=0.0,
        metavar="T",
        help="Checkpoint every T seconds",
    )

    p_show = sub.add_parser("show", help="Pretty-print a run tree")
    p_show.add_argument("run_id", help="Run ID or .tine file path")

    p_verify = sub.add_parser("verify", help="Verify a .tine integrity digest (and signature)")
    p_verify.add_argument("run_id", help="Run ID or .tine file path")
    p_verify.add_argument("--key-env", metavar="NAME", help="HMAC key from this env var")
    p_verify.add_argument("--key-file", metavar="PATH", help="HMAC key from this file")
    p_verify.add_argument("--pubkey", metavar="PATH", help="Ed25519 public key file")
    p_verify.add_argument(
        "--require-signature", action="store_true", help="Fail if no valid signature"
    )
    p_verify.add_argument(
        "--trust-embedded-key",
        action="store_true",
        help="Trust the artifact's embedded Ed25519 key (TOFU)",
    )

    p_sign = sub.add_parser("sign", help="Sign a .tine artifact")
    p_sign.add_argument("run_id", help="Run ID or .tine file path")
    p_sign.add_argument("--algorithm", choices=("hmac-sha256", "ed25519"), default="hmac-sha256")
    p_sign.add_argument("--key-env", metavar="NAME", help="HMAC key from this env var")
    p_sign.add_argument("--key-file", metavar="PATH", help="HMAC key from this file")
    p_sign.add_argument("--ed25519-key-file", metavar="PATH", help="Ed25519 private key file")
    p_sign.add_argument("--key-id", help="Optional key identifier recorded in the signature")
    p_sign.add_argument("--signer", help="Optional signer label (display only, not an identity)")
    p_sign.add_argument("--save", help="Write the signed artifact here (default: in place)")
    p_sign.add_argument(
        "--force", action="store_true", help="Sign despite a failed integrity check"
    )

    p_keygen = sub.add_parser("keygen", help="Generate an Ed25519 signing keypair")
    p_keygen.add_argument("--out", help="Write the private seed here (and PUB.pub)")
    p_keygen.add_argument("--pub", help="Write the public key here")

    p_migrate = sub.add_parser("migrate", help="Upgrade a .tine artifact to the current format")
    p_migrate.add_argument("run_id", help="Run ID or .tine file path")
    p_migrate.add_argument(
        "--to", type=int, default=None, help=f"Target format version (default {FORMAT_VERSION})"
    )
    p_migrate.add_argument("--dry-run", action="store_true", help="Preview without writing")
    p_migrate.add_argument("--in-place", action="store_true", help="Overwrite the source file")
    p_migrate.add_argument("--save", help="Write the migrated artifact to this path")
    p_migrate.add_argument(
        "--force", action="store_true", help="Migrate despite a failed source check / overwrite"
    )

    p_ls = sub.add_parser("ls", help="List recent runs (with optional filters)")
    _add_filter_args(p_ls)
    p_ls.add_argument("--limit", type=int, default=20, help="Max rows to show")

    p_search = sub.add_parser("search", help="Search runs with a query DSL")
    p_search.add_argument(
        "query",
        nargs="*",
        help="tag:x model:y status:z cost:>0.01 after:YYYY-MM-DD plus free text",
    )

    p_tag = sub.add_parser("tag", help="Add, remove, or list tags on a run")
    p_tag.add_argument("run_id", help="Run ID or .tine file path")
    p_tag.add_argument("--add", action="append", default=[], metavar="TAG", help="Tag to add")
    p_tag.add_argument("--remove", action="append", default=[], metavar="TAG", help="Tag to remove")
    p_tag.add_argument("--list", action="store_true", help="List current tags")

    sub.add_parser("reindex", help="Rebuild the run index")

    p_cost = sub.add_parser("cost", help="Show cost/usage breakdown and budget state")
    p_cost.add_argument("run_id", help="Run ID or .tine file path")

    p_fork = sub.add_parser("fork", help="Fork a run from a specific step")
    p_fork.add_argument("run_id", help="Run ID or .tine file path")
    p_fork.add_argument(
        "--from-step",
        required=True,
        help="Step index, full id, or unique id prefix",
    )
    p_fork.add_argument("--save", help="Output path for forked run")
    p_fork.add_argument("--force", action="store_true", help="Allow overwriting --save output")
    _add_harness_args(p_fork)

    p_replay = sub.add_parser("replay", help="Replay a run")
    p_replay.add_argument("run_id", help="Run ID or .tine file path")
    p_replay.add_argument(
        "--from-step",
        default=None,
        help="Step index, full id, or unique id prefix",
    )
    p_replay.add_argument("--mode", choices=("cache", "rerun"), default="cache", help="Replay mode")
    p_replay.add_argument(
        "--inspect",
        action="store_true",
        help="Print recorded steps instead of replaying",
    )
    p_replay.add_argument("--dry-run", action="store_true", help="Alias for --inspect")
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


def _add_filter_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--tag", action="append", default=[], metavar="TAG", help="Require this tag"
    )
    parser.add_argument("--model", help="Substring match on model")
    parser.add_argument("--status", help="Exact status (completed/failed/paused/running)")
    parser.add_argument("--cost-min", type=float, default=None, help="Minimum total cost")
    parser.add_argument("--cost-max", type=float, default=None, help="Maximum total cost")
    parser.add_argument("--since", help="Only runs created on/after this date (YYYY-MM-DD)")
    parser.add_argument("--until", help="Only runs created on/before this date (YYYY-MM-DD)")
    parser.add_argument(
        "--grep", action="append", default=[], metavar="TEXT", help="Free-text substring (AND)"
    )


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
    parser.add_argument(
        "--harness-login-env",
        action="store_true",
        help="Pass PATH, home/config directories, and tool-specific config env to the harness",
    )
    parser.add_argument(
        "--harness-env",
        action="append",
        default=[],
        metavar="NAME",
        help="Additional environment variable name to pass with --harness-login-env",
    )


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    commands = {
        "run": cmd_run,
        "show": cmd_show,
        "verify": cmd_verify,
        "sign": cmd_sign,
        "keygen": cmd_keygen,
        "migrate": cmd_migrate,
        "ls": cmd_ls,
        "search": cmd_search,
        "tag": cmd_tag,
        "reindex": cmd_reindex,
        "cost": cmd_cost,
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
