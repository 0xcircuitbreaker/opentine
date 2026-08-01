"""Rich renderers for run trees, file-index rows, costs, and diffs."""

from __future__ import annotations

from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from opentine._cli_common import (
    BRAND,
    BRAND_DIM,
    _cost_str,
    _display_value,
    _step_label,
    _terminal,
    console,
)
from opentine.core import Run, short_id
from opentine.index import IndexEntry, Query, _parse_date

STATUS_COLORS = {"completed": "green", "failed": "red", "paused": "yellow", "running": "cyan"}


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
    if budget.strict_cost:
        parts.append("strict_cost=true")
    parts.append(f"on_breach={budget.on_breach}")
    return ", ".join(parts)


def _print_run_tree(run: Run) -> None:
    color = STATUS_COLORS.get(run.status.value, "white")
    header = (
        f"[bold {BRAND}]#[/] [bold]{_terminal(short_id(run.id))}[/]  "
        f"model=[dim]{_terminal(run.model_info)}[/]  "
        f"steps=[dim]{len(run.steps)}[/]  cost=[dim]{_cost_str(run.total_cost)}[/]  "
        f"[{color}]{run.status.value}[/]"
    )
    tree = Tree(Text.from_markup(header))
    for step in run.steps:
        label = _step_label(step)
        if step.cost > 0:
            label.append(f"  {_cost_str(step.cost)}", style="dim")
        if step.duration > 0:
            label.append(f"  {step.duration:.1f}s", style="dim")
        tree.add(label)
    console.print()
    console.print(tree)
    console.print()
    if run.metadata.get("forked_from"):
        console.print(
            f"  [{BRAND_DIM}]Forked from:[/] {_terminal(run.metadata['forked_from'])} "
            f"at step {_terminal(run.metadata.get('fork_point', '?'))}",
            markup=True,
        )
    if run.budget():
        console.print(f"  [{BRAND_DIM}]budget:[/] {_budget_str(run.budget())}")
    state = run.metadata.get("budget_state")
    if isinstance(state, dict) and state.get("breached"):
        console.print(
            f"  [red]over budget:[/] {_terminal(state.get('dimension'))} "
            f"{_terminal(state.get('incurred'))} > {_terminal(state.get('limit'))}",
            highlight=False,
        )


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


def _query_from_ls_args(args) -> Query:
    query = Query()
    query.tags = [tag.strip().lower() for tag in (args.tag or []) if tag.strip()]
    query.model = args.model.lower() if args.model else None
    query.status = args.status.lower() if args.status else None
    query.cost_min, query.cost_max = args.cost_min, args.cost_max
    query.after = _parse_date(args.since) if args.since else None
    query.before = _parse_date(args.until) if args.until else None
    query.text = [value.lower() for value in (args.grep or [])]
    return query


def _entries_table(title: str, entries: list[IndexEntry], *, show_unreadable: bool) -> Table:
    table = Table(title=f"[{BRAND}]{_terminal(title)}[/]", border_style=BRAND_DIM)
    for label, style, justify in (
        ("ID", "bold", "left"),
        ("Status", "", "left"),
        ("Model", "dim", "left"),
        ("Steps", "", "right"),
        ("Cost", "", "right"),
        ("Tags", BRAND_DIM, "left"),
        ("File", "dim", "left"),
    ):
        table.add_column(label, style=style, justify=justify)
    for entry in entries:
        if entry.unreadable:
            if show_unreadable:
                table.add_row("?", "[red]corrupt[/]", "", "", "", "", _terminal(entry.file))
            continue
        status = f"[{STATUS_COLORS.get(entry.status, 'white')}]{_terminal(entry.status)}[/]"
        table.add_row(
            _terminal(short_id(entry.run_id)),
            status,
            _terminal(entry.model),
            str(entry.steps),
            _cost_str(entry.cost),
            _terminal(", ".join(entry.tags)),
            _terminal(entry.file),
        )
    return table


def _print_diff_table(left: Run, right: Run) -> None:
    table = Table(
        title=f"[{BRAND}]Diff: {_terminal(short_id(left.id))} "
        f"vs {_terminal(short_id(right.id))}[/]",
        border_style=BRAND_DIM,
    )
    for column in ("#", _terminal(short_id(left.id)), _terminal(short_id(right.id)), "Match"):
        table.add_column(column)
    diff = left.diff(right)
    common = _terminal(short_id(diff.common_ancestor)) if diff.common_ancestor else "-"
    table.add_row("base", common, common, "[green]=[/]" if diff.common_ancestor else "!")
    for step in diff.only_a:
        table.add_row("", _step_label(step), "---", "only A")
    for step in diff.only_b:
        table.add_row("", "---", _step_label(step), "only B")
    for change in diff.changed:
        table.add_row(
            "",
            _step_label(change.step_a),
            _step_label(change.step_b),
            "changed",
        )
        for delta in change.fields:
            keys = f" [{', '.join(delta.changed_keys)}]" if delta.changed_keys else ""
            label = _terminal(delta.name + keys)
            table.add_row(
                "",
                f"[red]- {label}: {_terminal(_display_value(delta.before))[:48]}[/]",
                f"[green]+ {label}: {_terminal(_display_value(delta.after))[:48]}[/]",
                "",
            )
    console.print(table)


def print_replay_verify(verdict) -> None:
    """Render one ``tine replay --verify`` verdict (the object ``--json`` emits)."""
    headline = "[green]REPRODUCED[/]" if verdict.reproduced else "[red]DRIFT[/]"
    console.print(
        f"[{BRAND}]# Replay verify[/] ({verdict.mode}) {_terminal(short_id(verdict.run_id))} -> "
        f"{_terminal(short_id(verdict.replay_id))} {headline}"
    )
    if verdict.reused_steps is not None:
        console.print(
            f"reused {verdict.reused_steps} recorded steps (expected {verdict.expected_steps})"
        )
    digest = verdict.integrity.actual or verdict.integrity.expected or ""
    state = "verified" if verdict.integrity.ok else f"FAILED: {verdict.integrity.reason}"
    console.print(f"round trip sha256:{_terminal(digest[:12])} {_terminal(state)}")
    if not verdict.identity_ok:
        console.print(f"[red]identity drift:[/] {_terminal(short_id(verdict.second_id))}")
    if verdict.slice_ok is False:
        console.print("[red]retained slice differs from the expected closure[/]")
    if verdict.structural:
        console.print(f"[red]structural drift:[/] {_terminal(', '.join(verdict.structural))}")
    if verdict.accounting:
        note = " [dim](ignored)[/]" if verdict.ignore_cost_drift else ""
        drift = _terminal(", ".join(verdict.accounting))
        console.print(f"[yellow]accounting drift:[/] {drift}{note}")
