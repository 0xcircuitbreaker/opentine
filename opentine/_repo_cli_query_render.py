"""Human rendering for the two v3 query verbs: ``repo-diff`` and ``repo-search``.

Split out of ``opentine._repo_cli_render`` for one reason only — the 250-line
module gate — so the same rules hold here verbatim. Everything these tables
print is *recorded content*: event oids, model ids, tool names, and, in
``repo-search``, a prefix of raw blob text a model read. All of it reaches the
console through ``opentine._cli_common._terminal``, and the shortener and
number-coercion helpers are imported from the sibling module rather than
re-implemented, so a v3 oid can never be abbreviated two different ways.

The tables are modelled on the .tine renderers they sit beside:
``render_diff`` on ``_cli_render._print_diff_table`` and ``render_search`` on
``_cli_render._entries_table``. Neither can be reused directly — those take
``Run`` and ``IndexEntry`` objects, while these take a ``SemanticDiff`` and
``SearchResult`` rows, which name events by oid and report *which* fields
changed rather than their before/after values.
"""

from __future__ import annotations

from typing import Any

from rich.table import Table

from opentine._cli_common import BRAND, BRAND_DIM, _cost_str, _display_value, _terminal
from opentine._cli_render import STATUS_COLORS
from opentine._repo_cli_render import _number, _short_oid

#: Tool names shown on the summary line before the path is elided.
_PATH_STEPS = 8


def _tool_path(values: Any) -> str:
    """The tool names one side walked, escaped and bounded to a single line.

    ``summary["tool_path"]`` holds the raw ``tool`` field of every present event,
    which is whatever the recorder wrote: usually ``{"name": …, "arguments": …}``,
    but an empty object for a non-tool step, and possibly a string or null.
    """
    entries = list(values or [])
    names: list[str] = []
    for entry in entries[:_PATH_STEPS]:
        name = entry.get("name") if isinstance(entry, dict) else entry
        # Truncate first, escape second, as everywhere else on this surface.
        names.append(_terminal(_display_value(name)[:24]) if name else "-")
    if len(entries) > _PATH_STEPS:
        names.append("…")
    return " > ".join(names) or "-"


def _sides(summary: dict[str, Any], name: str) -> tuple[Any, Any]:
    side = summary.get(name)
    side = side if isinstance(side, dict) else {}
    return side.get("left"), side.get("right")


def _present(value: Any) -> int:
    """Count non-empty entries: ``artifacts`` holds one slot per event, mostly null."""
    return sum(1 for item in value or [] if item)


def _seconds(value: Any) -> str:
    return f"{_number(value) or 0.0:.1f}s"


def render_diff_summary(console: Any, summary: Any) -> None:
    """The five ``SemanticDiff.summary`` dimensions, left value then right."""
    if not isinstance(summary, dict):
        return
    left_cost, right_cost = _sides(summary, "cost")
    left_latency, right_latency = _sides(summary, "latency")
    left_artifacts, right_artifacts = _sides(summary, "artifacts")
    left_scores, right_scores = _sides(summary, "evaluations")
    left_tools, right_tools = _sides(summary, "tool_path")
    rows = (
        ("cost", _cost_str(_number(left_cost) or 0.0), _cost_str(_number(right_cost) or 0.0)),
        ("latency", _seconds(left_latency), _seconds(right_latency)),
        ("artifacts", str(_present(left_artifacts)), str(_present(right_artifacts))),
        ("evaluations", str(_present(left_scores)), str(_present(right_scores))),
        ("tool path", _tool_path(left_tools), _tool_path(right_tools)),
    )
    console.print()
    for label, left, right in rows:
        # highlight=False: every one of these values came out of a payload, and
        # Rich's repr highlighter would restyle anything that looks like a number.
        console.print(f"  [{BRAND_DIM}]{label}:[/] {left}  [dim]->[/]  {right}", highlight=False)
    console.print()


def render_diff(console: Any, left_id: str, right_id: str, diff: Any) -> None:
    """The divergence table, then the summary block."""
    left_label, right_label = _short_oid(left_id), _short_oid(right_id)
    table = Table(
        title=f"[{BRAND}]Diff: {left_label} vs {right_label}[/]",
        border_style=BRAND_DIM,
    )
    for column in ("#", left_label, right_label, "Match"):
        table.add_column(column)
    common = str(len(diff.common_events))
    table.add_row("common", common, common, "[green]=[/]" if diff.common_events else "!")
    for oid in diff.only_left:
        table.add_row("", _short_oid(oid), "---", "only left")
    for oid in diff.only_right:
        table.add_row("", "---", _short_oid(oid), "only right")
    for change in diff.changed:
        fields = ", ".join(str(name) for name in change.get("fields") or [])
        table.add_row(
            _terminal(change.get("index", "")),
            f"[red]- {_short_oid(change.get('before'))}[/]",
            f"[green]+ {_short_oid(change.get('after'))}[/]",
            f"changed: {_terminal(fields)}" if fields else "changed",
        )
    console.print(table)
    render_diff_summary(console, diff.summary)


def render_search(console: Any, query: str, results: list[Any]) -> None:
    """One row per matching run; ``Match`` is a prefix of the blob text that matched."""
    title = f"repo-search: {len(results)} run(s)"
    if query:
        title += f' matching "{_terminal(query[:48])}"'
    table = Table(title=f"[{BRAND}]{title}[/]", border_style=BRAND_DIM)
    for label, style, justify in (
        ("Run", "bold", "left"),
        ("Status", "", "left"),
        ("Score", "", "right"),
        ("Cost", "", "right"),
        ("Latency", "", "right"),
        ("Models", "dim", "left"),
        ("Match", BRAND_DIM, "left"),
    ):
        table.add_column(label, style=style, justify=justify)
    for result in results:
        score = _number(result.score)
        table.add_row(
            _short_oid(result.run_id),
            f"[{STATUS_COLORS.get(result.status, 'white')}]{_terminal(result.status)}[/]",
            "-" if score is None else f"{score:.2f}",
            _cost_str(_number(result.cost) or 0.0),
            _seconds(result.latency),
            _terminal(", ".join(str(model) for model in result.models)[:32]),
            _terminal(str(result.matched_text)[:64]),
        )
    console.print(table)
