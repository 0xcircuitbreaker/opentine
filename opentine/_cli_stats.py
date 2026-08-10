"""Cross-run aggregation over the legacy ``.tine_runs`` file index.

Scope, stated here and repeated verbatim in the help text and in ``--json``:
``tine stats`` reads the same rebuildable index ``tine ls`` and ``tine search``
read, and nothing else. It does not walk v3 repositories — aggregating those is
the v3 search engine's job and a ``--repo`` mode is deferred to a later release. The
``scope`` field is what tells a script that a small number is small because of
what was *counted*.

The rule that shapes everything below: :class:`~opentine._index_types.IndexEntry`
carries no token counts and no durations. Without ``--deep`` those keys are
**absent** from every object this module builds — never ``0``, never ``null``.
Not-collected has to be indistinguishable from nothing-said, never from
nothing-spent, because a zero here reads as "this run was free" and would be
summed with real costs by whatever consumes it. ``--deep`` opts into loading
each matched run (bounded by ``MAX_INDEX_RUNS``) and only then do the token and
duration keys exist at all.

Filters are the whole ``tine ls`` set, through the same ``_query_from_ls_args``
+ ``match_entry`` pair, so parity is structural rather than re-implemented.
``match_entry`` never matches an unreadable row, so the corrupt-artifact count
is reported *separately* instead of vanishing from the denominator.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime

from rich.table import Table

from opentine._cli_common import BRAND, BRAND_DIM, _cost_str, _runs_dir, _terminal, console
from opentine._cli_json_flow import STATS_SCOPE_NOTE, emit_stats
from opentine._cli_listing import _index
from opentine._cli_render import _query_from_ls_args
from opentine.core import Run
from opentine.index import MAX_INDEX_RUNS, IndexEntry, QueryError, match_entry

#: The ``--group-by`` choices, in the order the help lists them.
GROUP_BY_CHOICES = ("model", "status", "tag", "day", "format-version")
NONE_KEY = "(none)"
UNTAGGED = "(untagged)"
UNDATED = "(undated)"

#: Per-run deep facts, keyed by index file name: input tokens, output tokens, seconds.
_DeepTotals = dict[str, tuple[int, int, float]]


def _load_deep(entries: list[IndexEntry]) -> tuple[_DeepTotals, int]:
    """Load every matched run for the facts the index does not carry.

    Returns the per-file totals and the number of runs that would not load. The
    failures are reported rather than folded in, for the same reason the token
    keys are absent without ``--deep``: a run that could not be read is not a
    run that cost nothing.
    """
    runs_dir = _runs_dir()
    loaded: _DeepTotals = {}
    failed = 0
    for entry in entries:
        try:
            run = Run.load(runs_dir / entry.file)
            breakdown = run.cost_breakdown()
            duration = float(sum(float(step.duration) for step in run.steps))
        except Exception:
            failed += 1
            continue
        loaded[entry.file] = (breakdown.input_tokens, breakdown.output_tokens, duration)
    return loaded, failed


def _histogram(values: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def aggregate(entries: list[IndexEntry], deep: _DeepTotals | None = None) -> dict:
    """One aggregate row over *entries*, using only ``IndexEntry`` fields.

    *deep* is ``None`` unless ``--deep`` collected them; when it is, and only
    then, the token and duration keys are added.
    """
    count = len(entries)
    steps = sum(entry.steps for entry in entries)
    costs = [float(entry.cost) for entry in entries]
    times = [entry.created_at for entry in entries]
    row = {
        "runs": count,
        "steps_total": steps,
        "steps_mean": (steps / count) if count else 0.0,
        "cost_total": sum(costs),
        "cost_mean": (sum(costs) / count) if count else 0.0,
        "cost_max": max(costs) if costs else 0.0,
        "models": sorted({entry.model or NONE_KEY for entry in entries}),
        "tags": _histogram([tag for entry in entries for tag in entry.tags]),
        "format_versions": _histogram([str(entry.format_version) for entry in entries]),
        "first_created_at": min(times) if times else None,
        "last_created_at": max(times) if times else None,
    }
    if deep is None:
        return row
    facts = [deep[entry.file] for entry in entries if entry.file in deep]
    inputs = sum(fact[0] for fact in facts)
    outputs = sum(fact[1] for fact in facts)
    seconds = sum(fact[2] for fact in facts)
    row.update(
        {
            "input_tokens": inputs,
            "output_tokens": outputs,
            "total_tokens": inputs + outputs,
            "duration_total": seconds,
            "duration_mean": (seconds / len(facts)) if facts else 0.0,
        }
    )
    return row


def _day(entry: IndexEntry) -> str:
    try:
        return datetime.fromtimestamp(entry.created_at, UTC).strftime("%Y-%m-%d")
    except (OSError, OverflowError, ValueError):
        return UNDATED


def group_keys(entry: IndexEntry, group_by: str) -> list[str]:
    """Every group *entry* belongs to; a multi-tagged run counts under each tag."""
    if group_by == "model":
        return [entry.model or NONE_KEY]
    if group_by == "status":
        return [entry.status or NONE_KEY]
    if group_by == "format-version":
        return [str(entry.format_version)]
    if group_by == "day":
        return [_day(entry)]
    return sorted(set(entry.tags)) or [UNTAGGED]


def group_rows(
    entries: list[IndexEntry], group_by: str, deep: _DeepTotals | None, limit: int
) -> list[dict]:
    """Aggregate per group, ordered cost desc then key asc so output diffs cleanly."""
    buckets: dict[str, list[IndexEntry]] = {}
    for entry in entries:
        for key in group_keys(entry, group_by):
            buckets.setdefault(key, []).append(entry)
    rows = [{"key": key, **aggregate(members, deep)} for key, members in buckets.items()]
    rows.sort(key=lambda row: (-row["cost_total"], row["key"]))
    return rows[:limit] if limit and limit > 0 else rows


def _stamp(value: float | None) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d %H:%M")
    except (OSError, OverflowError, ValueError):
        return "-"


def _print_stats(
    totals: dict, groups: list[dict], group_by: str | None, unreadable: int, failed: int | None
) -> None:
    console.print(
        f"[{BRAND}]# Stats[/] {totals['runs']} run(s)  "
        f"steps={totals['steps_total']} (mean {totals['steps_mean']:.1f})  "
        f"cost={_cost_str(totals['cost_total'])} "
        f"(mean {_cost_str(totals['cost_mean'])}, max {_cost_str(totals['cost_max'])})"
    )
    if "total_tokens" in totals:
        console.print(
            f"  tokens={totals['total_tokens']} "
            f"(in {totals['input_tokens']}, out {totals['output_tokens']})  "
            f"duration={totals['duration_total']:.1f}s"
        )
    console.print(
        f"  window: {_stamp(totals['first_created_at'])} .. {_stamp(totals['last_created_at'])}"
    )
    console.print(f"  models: {_terminal(', '.join(totals['models'])) or '-'}")
    versions = ", ".join(f"v{key}={count}" for key, count in totals["format_versions"].items())
    console.print(f"  format versions: {_terminal(versions) or '-'}")
    if unreadable:
        console.print(f"  [red]unreadable:[/] {unreadable} (excluded from every number above)")
    if failed:
        console.print(f"  [yellow]--deep could not load:[/] {failed} run(s)")
    if group_by:
        console.print(_groups_table(groups, group_by))
    console.print(f"[{BRAND_DIM}]{STATS_SCOPE_NOTE}[/]")


def _groups_table(groups: list[dict], group_by: str) -> Table:
    deep = any("total_tokens" in row for row in groups)
    table = Table(title=f"[{BRAND}]By {_terminal(group_by)}[/]", border_style=BRAND_DIM)
    columns = ["Key", "Runs", "Steps", "Cost", "Mean cost"]
    if deep:
        columns += ["Tokens", "Duration"]
    for index, label in enumerate(columns):
        table.add_column(label, justify="left" if index == 0 else "right")
    for row in groups:
        cells = [
            _terminal(row["key"]),
            str(row["runs"]),
            str(row["steps_total"]),
            _cost_str(row["cost_total"]),
            _cost_str(row["cost_mean"]),
        ]
        if deep:
            cells += [str(row.get("total_tokens", 0)), f"{row.get('duration_total', 0.0):.1f}s"]
        table.add_row(*cells)
    return table


def cmd_stats(args: argparse.Namespace) -> None:
    index = _index()
    try:
        query = _query_from_ls_args(args)
    except QueryError as exc:
        console.print(f"[red]Bad filter:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    entries = list(index.entries.values())
    # match_entry never matches an unreadable row, so these are counted apart
    # rather than quietly dropped: "12 runs" with three corrupt files nearby is
    # a different fact from "12 runs".
    unreadable = sum(1 for entry in entries if entry.unreadable)
    matched = [entry for entry in entries if not entry.unreadable and match_entry(entry, query)]
    if len(matched) > MAX_INDEX_RUNS:
        console.print(f"[red]Cannot aggregate:[/] more than {MAX_INDEX_RUNS} runs matched.")
        raise SystemExit(1)
    deep: _DeepTotals | None = None
    failed: int | None = None
    if getattr(args, "deep", False):
        deep, failed = _load_deep(matched)
    totals = aggregate(matched, deep)
    group_by = getattr(args, "group_by", None)
    groups = group_rows(matched, group_by, deep, args.limit) if group_by else []
    if getattr(args, "json", False):
        emit_stats(
            totals=totals,
            groups=groups,
            group_by=group_by,
            deep=deep is not None,
            unreadable=unreadable,
            deep_failed=failed,
        )
        return
    _print_stats(totals, groups, group_by, unreadable, failed)
