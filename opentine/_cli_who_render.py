"""Human and JSON output for the action commands (``who``, ``actions`` ...).

Every recorded string here is untrusted run content, so it reaches the
terminal only through ``_terminal`` (markup escaped, control bytes dropped);
``--json`` goes through the shared ``serialize``.
"""

from __future__ import annotations

import argparse
import time
from collections.abc import Callable
from typing import Any

from rich.table import Table

from opentine._actions import Action
from opentine._agent_identity import lookalike
from opentine._cli_common import BRAND, _terminal, console
from opentine._cli_json import emit


def emit_or_print(
    args: argparse.Namespace, command: str, payload: dict[str, Any], human: Callable[[], None]
) -> None:
    if getattr(args, "json", False):
        emit({"command": command, **payload})
    else:
        human()


def _when(ts: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) if ts else "-"


def _coverage_note(coverage: dict[str, int] | None) -> None:
    if not coverage:
        return
    notes = []
    if coverage.get("redacted_unmatched"):
        notes.append(
            f"{coverage['redacted_unmatched']} action(s) have redacted command text "
            "that could hide a match"
        )
    if coverage.get("redacted_commands"):
        notes.append(
            f"{coverage['redacted_commands']} command(s) were partly redacted, so a rule "
            "may not have seen the whole command (--allow-partial to accept)"
        )
    if coverage.get("unreadable_runs"):
        notes.append(f"{coverage['unreadable_runs']} run(s) could not be read")
    if coverage.get("truncated_runs"):
        notes.append(f"{coverage['truncated_runs']} run(s) hit the per-run action cap")
    for note in notes:
        console.print(f"[yellow]Note:[/] {note}.")


def render_groups(
    keys: list[str], groups: list[dict[str, Any]], matched: int, coverage: dict[str, int]
) -> None:
    if not groups:
        console.print(f"[dim]No matching actions across {coverage.get('runs', 0)} run(s).[/]")
        _coverage_note(coverage)
        return
    table = Table(title=f"{matched} matching action(s)", header_style=f"bold {BRAND}")
    for key in keys:
        table.add_column(key)
    trusted = any("trust" in row for row in groups)
    for column in ("actions", "errors", "runs", "first", "last", "sample runs"):
        table.add_column(
            column, justify="right" if column in ("actions", "errors", "runs") else "left"
        )
    if trusted:
        table.add_column("trust")
    for row in groups:
        table.add_row(
            *[_terminal(row[key]) for key in keys],
            str(row["actions"]),
            str(row["errors"]),
            str(row["run_count"]),
            _when(row["first"]),
            _when(row["last"]),
            _terminal(", ".join(run[:12] for run in row["sample_runs"])),
            *([_terminal(row.get("trust", ""))] if trusted else []),
        )
    console.print(table)
    _coverage_note(coverage)


def _detail(action: Action) -> str:
    if action.command:
        return action.command
    if action.mcp_server:
        return f"{action.mcp_server}/{action.mcp_tool}"
    return ", ".join([*action.paths, *action.hosts])


def _agent(action: Action) -> str:
    # A name that is not plain ASCII after NFKC may imitate another agent's.
    flag = " (!look-alike)" if lookalike(action.agent) else ""
    return _terminal(action.agent or "-") + flag


def render_actions(
    title: str,
    actions: list[Action],
    coverage: dict[str, int] | None,
    *,
    timeline: bool = False,
    trust: dict[str, str] | None = None,
) -> None:
    if not actions:
        console.print("[dim]No actions.[/]")
        _coverage_note(coverage)
        return
    table = Table(title=_terminal(title), header_style=f"bold {BRAND}")
    columns = (
        ("#", "time", "tool", "verb", "detail")
        if timeline
        else ("run", "agent", "trust", "model", "tool", "verb", "detail")
    )
    for column in columns:
        table.add_column(column)
    for action in actions:
        flag = " [red](error)[/]" if action.error else ""
        detail = _terminal(_detail(action)[:240]) + flag
        verbs = _terminal(",".join(action.verbs))
        if timeline:
            table.add_row(str(action.seq), _when(action.ts), _terminal(action.tool), verbs, detail)
        else:
            table.add_row(
                _terminal(action.run_id[:12]),
                _agent(action),
                _terminal((trust or {}).get(action.run_id, "unsigned")),
                _terminal(action.model or "-"),
                _terminal(action.tool),
                verbs,
                detail,
            )
    console.print(table)
    _coverage_note(coverage)


def _signatures(trust: dict[str, Any] | None) -> None:
    if not trust:
        return
    counts: dict[str, int] = {}
    for state in trust["states"].values():
        counts[state] = counts.get(state, 0) + 1
    summary = ", ".join(f"{count} {state}" for state, count in sorted(counts.items()))
    console.print(f"Signatures: {_terminal(summary or 'no runs')}.")
    for run_id in trust["unverified"]:
        state = trust["states"][run_id]
        console.print(f"[red]not verified[/] {_terminal(run_id[:64])}: {_terminal(state)}")


def print_audit(
    violations: list[Any], rules: int, coverage: dict[str, int], trust: dict | None = None
) -> None:
    _signatures(trust)
    partial = any(
        coverage.get(key) for key in ("unreadable_runs", "truncated_runs", "redacted_commands")
    )
    if not violations:
        color = "yellow" if partial else "green"
        console.print(
            f"[{color}]No violations[/] of {rules} rule(s) across {coverage['runs']} run(s)"
            + (", but not every action could be checked." if partial else ".")
        )
        _coverage_note(coverage)
        return
    _coverage_note(coverage)
    for violation in violations:
        action, color = violation.action, "red" if violation.rule.level == "deny" else "yellow"
        detail = action.command or ", ".join(action.paths) or action.tool
        console.print(
            f"[{color}]{violation.rule.level}[/] {_terminal(violation.rule.id)}: "
            f"{_agent(action)} {_terminal(action.run_id[:16])} "
            f"{_terminal(action.tool)} {_terminal(detail[:200])}"
        )


__all__ = ["emit_or_print", "print_audit", "render_actions", "render_groups"]
