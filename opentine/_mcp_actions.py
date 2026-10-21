"""MCP ``find_actions``: which agents did what, for a model client.

The same action index and query as ``tine who``. Every argument is bounded,
every filter is a bound SQL parameter, and the result goes through the shared
``visible()`` sanitizer (via ``safe_errors``) like every other tool result.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine._actions_query import GROUP_KEYS, ActionQuery, find, group, parse_time
from opentine._actions_source import open_repo, open_runs_dir
from opentine._mcp_safety import safe_errors

MAX_MCP_ACTION_RESULTS = 500
MAX_MCP_FILTER_CHARS = 1024


def _bounded(name: str, value: Any) -> Any:
    if value is not None and (not isinstance(value, str) or len(value) > MAX_MCP_FILTER_CHARS):
        raise ValueError(f"{name} must be a string of at most {MAX_MCP_FILTER_CHARS} characters")
    return value


def register_action_tools(mcp: Any, runs_dir: str | Path, repo_path: str | Path) -> None:
    mcp = safe_errors(mcp)

    @mcp.tool()
    def find_actions(
        tool: str | None = None,
        cmd: str | None = None,
        program: str | None = None,
        path: str | None = None,
        host: str | None = None,
        mcp_server: str | None = None,
        verb: str | None = None,
        agent: str | None = None,
        model: str | None = None,
        since: str | None = None,
        source: str = "runs",
        group_by: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Find recorded agent actions (tool calls, commands, paths, hosts, MCP calls).

        ``source`` is ``runs`` (the legacy runs directory) or ``repo`` (the v3
        repository). ``group_by`` is a comma list of agent, model, provider,
        session, subagent, run, tool, program; without it, matching actions are
        listed. Command text is searched redacted, as it was recorded.
        """
        filters = {
            "tool": tool,
            "cmd": cmd,
            "program": program,
            "path": path,
            "host": host,
            "mcp": mcp_server,
            "verb": verb,
            "agent": agent,
            "model": model,
        }
        for name, value in [*filters.items(), ("since", since), ("group_by", group_by)]:
            _bounded(name, value)
        if source not in ("runs", "repo"):
            raise ValueError("source must be runs or repo")
        if type(limit) is not int or not 1 <= limit <= MAX_MCP_ACTION_RESULTS:
            raise ValueError(f"limit must be 1 to {MAX_MCP_ACTION_RESULTS}")
        query = ActionQuery(cmd=[cmd] if cmd else [])
        for name, value in filters.items():
            if value and name != "cmd":
                setattr(query, name, value)
        if since:
            query.since = parse_time(since)
        if source == "repo":
            from opentine.repo import Repo

            index, _ = open_repo(Repo.open(repo_path))
        else:
            index, _ = open_runs_dir(Path(runs_dir))
        with index:
            matched = find(index, query)
            coverage = index.coverage()
        if group_by:
            keys = [key.strip() for key in group_by.split(",") if key.strip()]
            if not keys or any(key not in GROUP_KEYS for key in keys):
                raise ValueError(f"group_by takes a comma list of: {', '.join(GROUP_KEYS)}")
            return {
                "groups": group(matched, keys, program=query.program)[:limit],
                "matched": len(matched),
                "coverage": coverage,
            }
        return {
            "actions": [action.to_dict() for action in matched[:limit]],
            "matched": len(matched),
            "coverage": coverage,
        }


def register_actions_and_repository(mcp: Any, runs_dir: str | Path, repo_path: str | Path) -> None:
    """``find_actions``, then the v3 repository tools when a repository exists."""
    register_action_tools(mcp, runs_dir, repo_path)
    try:
        from opentine.mcp_repository import register_repository_tools

        register_repository_tools(mcp, str(repo_path))
    except FileNotFoundError:
        pass


__all__ = ["register_action_tools", "register_actions_and_repository"]
