"""Filters, grouping and coverage for ``tine who`` / ``actions`` / ``touched``.

Every filter compiles to parameterized SQL over the action index: no user text
is ever spliced into a statement. A pattern with ``*``, ``?`` or ``[`` is a
glob; anything else is a case-insensitive substring (paths, tools, commands)
or a host-and-subdomains match (hosts).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from opentine._actions import Action
from opentine._actions_db import ActionIndex

GROUP_KEYS = (
    "agent",
    "agent_ref",
    "model",
    "provider",
    "session",
    "subagent",
    "run",
    "tool",
    "program",
)
MAX_RESULTS = 100_000
_GLOB = re.compile(r"[*?\[]")
_DURATION = re.compile(r"^(\d{1,9})([smhdw])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class ActionQueryError(ValueError):
    pass


@dataclass
class ActionQuery:
    tool: str | None = None
    cmd: list[str] = field(default_factory=list)
    program: str | None = None
    path: str | None = None
    host: str | None = None
    mcp: str | None = None
    verb: str | None = None
    agent: str | None = None
    model: str | None = None
    provider: str | None = None
    session: str | None = None
    run: str | None = None
    since: float | None = None
    until: float | None = None
    errors: bool = False
    writes: bool = False
    #: Exact, full-length agent refs (``--agent-ref`` / ``--lineage``); never a prefix.
    agent_refs: list[str] = field(default_factory=list)


def parse_time(value: str, *, now: float | None = None) -> float:
    """``7d``/``24h``/``30m``/``2w`` back from now, or an ISO date or datetime."""
    text = value.strip()
    if match := _DURATION.match(text):
        return (now if now is not None else time.time()) - int(match[1]) * _UNITS[match[2]]
    for form in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(text, form).replace(tzinfo=UTC).timestamp()
        except ValueError:
            continue
    raise ActionQueryError(f"invalid time {value!r}; use 7d, 24h, 30m or YYYY-MM-DD")


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _text(column: str, pattern: str, params: list[Any]) -> str:
    if _GLOB.search(pattern):
        params.append(pattern.lower())
        return f"lower({column}) GLOB ?"
    params.append(_like(pattern))
    return f"{column} LIKE ? ESCAPE '\\'"


def _member(column: str, value: str, params: list[Any]) -> str:
    params.append(_like("," + value.lower() + ","))
    return f"lower({column}) LIKE ? ESCAPE '\\'"


def compile_query(query: ActionQuery) -> tuple[str, tuple[Any, ...]]:
    """``WHERE ...`` and its parameters for *query* (``""`` when it filters nothing)."""
    clauses: list[str] = []
    params: list[Any] = []
    for column, value in (
        ("tool", query.tool),
        ("agent", query.agent),
        ("model", query.model),
        ("provider", query.provider),
        ("session", query.session),
    ):
        if value:
            clauses.append(_text(column, value, params))
    for term in query.cmd:
        clauses.append(_text("command", term, params))
    if query.agent_refs:
        params.extend(query.agent_refs)
        clauses.append(f"agent_ref IN ({', '.join('?' for _ in query.agent_refs)})")
    if query.program:
        clauses.append(_member("programs", query.program, params))
    if query.verb:
        clauses.append(_member("verbs", query.verb, params))
    if query.writes and not query.path:
        clauses.append("EXISTS (SELECT 1 FROM paths WHERE action_id = id AND written = 1)")
    if query.run:
        params.append(_like(query.run)[1:])
        clauses.append("run_id LIKE ? ESCAPE '\\'")
    if query.since is not None:
        clauses.append("ts >= ?")
        params.append(query.since)
    if query.until is not None:
        clauses.append("ts <= ?")
        params.append(query.until)
    if query.errors:
        clauses.append("error = 1")
    if query.path:
        inner = _text("path", query.path, params)
        role = " AND written = 1" if query.writes else ""
        clauses.append(f"EXISTS (SELECT 1 FROM paths WHERE action_id = id AND {inner}{role})")
    if query.host:
        host = query.host.lower().strip(".")
        if _GLOB.search(host):
            params.append(host)
            inner = "host GLOB ?"
        else:
            params.extend((host, _like("." + host).removesuffix("%")))
            inner = "(host = ? OR host LIKE ? ESCAPE '\\')"
        clauses.append(f"EXISTS (SELECT 1 FROM hosts WHERE action_id = id AND {inner})")
    if query.mcp:
        server, _, tool = query.mcp.partition("/")
        clauses.append(_text("mcp_server", server, params) if server else "mcp_server != ''")
        if tool:
            clauses.append(_text("mcp_tool", tool, params))
    return ("WHERE " + " AND ".join(clauses), tuple(params)) if clauses else ("", ())


def find(index: ActionIndex, query: ActionQuery, *, limit: int = MAX_RESULTS) -> list[Action]:
    where, params = compile_query(query)
    return list(index.rows(where, params, limit=min(limit, MAX_RESULTS)))


def redacted_misses(index: ActionIndex, query: ActionQuery) -> int:
    """Actions a ``--cmd`` term missed whose command text was partly redacted.

    Such an action *might* match under the redaction label, so a "no match"
    over it is not proof; reporting the count keeps coverage honest.
    """
    if not query.cmd:
        return 0
    loose = ActionQuery(**{**query.__dict__, "cmd": []})
    where, params = compile_query(loose)
    joined = f"{where} AND redacted = 1" if where else "WHERE redacted = 1"
    matched_where, matched_params = compile_query(query)
    matched = f"{matched_where} AND redacted = 1" if matched_where else "WHERE redacted = 1"
    return index.count(joined, params) - index.count(matched, matched_params)


def _key(action: Action, by: str, program: str | None) -> str:
    if by == "run":
        return action.run_id
    if by == "program":
        # Group under the program that matched a --program filter, not argv0:
        # `cd /x && git push` matched `git` and must not be labelled `cd`.
        wanted = (program or "").lower()
        matched = next((name for name in action.programs if name.lower() == wanted), "")
        return matched or action.argv0
    return str(getattr(action, by))


def group(
    actions: list[Action],
    by: list[str],
    *,
    program: str | None = None,
    trust: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Count *actions* per combination of the *by* fields, busiest group first.

    With *trust* (run id -> state), each group lists the states of its runs.
    """
    groups: dict[tuple[str, ...], dict[str, Any]] = {}
    for action in actions:
        key = tuple(_key(action, field_name, program) or "-" for field_name in by)
        entry = groups.setdefault(
            key,
            {
                **dict(zip(by, key, strict=True)),
                "actions": 0,
                "errors": 0,
                "runs": set(),
                "first": None,
                "last": None,
            },
        )
        entry["actions"] += 1
        entry["errors"] += int(action.error)
        entry["runs"].add(action.run_id)
        if action.ts:
            entry["first"] = min(filter(None, (entry["first"], action.ts)))
            entry["last"] = max(filter(None, (entry["last"], action.ts)))
    rows = []
    for entry in groups.values():
        runs = sorted(entry.pop("runs"))
        row = {**entry, "run_count": len(runs), "sample_runs": runs[:5]}
        if trust is not None:
            row["trust"] = ",".join(sorted({trust.get(run, "unsigned") for run in runs}))
        rows.append(row)
    rows.sort(key=lambda row: (-row["actions"], [str(row[name]) for name in by]))
    return rows


__all__ = [
    "GROUP_KEYS",
    "ActionQuery",
    "ActionQueryError",
    "compile_query",
    "find",
    "group",
    "parse_time",
    "redacted_misses",
]
