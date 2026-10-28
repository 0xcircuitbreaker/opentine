"""The action index's SQLite schema (``ACTIONS_SCHEMA`` 4 adds agent refs).

The index is a rebuildable cache: a database stamped by another schema or
opentine version is replaced wholesale on first use (see ``_actions_db``).
"""

from __future__ import annotations

COLUMNS = (
    "run_id step_id seq tool verbs agent session subagent model provider ts mcp_server "
    "mcp_tool argv0 programs command error cost redacted clipped agent_ref parent_ref"
).split()
SCHEMA = f"""
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sources (
    source TEXT PRIMARY KEY, stamp TEXT NOT NULL, run_id TEXT NOT NULL DEFAULT '',
    unreadable INTEGER NOT NULL DEFAULT 0, truncated INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY, source TEXT NOT NULL, {", ".join(COLUMNS)});
CREATE TABLE IF NOT EXISTS paths (
    action_id INTEGER NOT NULL, path TEXT NOT NULL, written INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS hosts (action_id INTEGER NOT NULL, host TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS actions_source ON actions(source);
CREATE INDEX IF NOT EXISTS actions_tool ON actions(tool);
CREATE INDEX IF NOT EXISTS actions_agent_ref ON actions(agent_ref);
CREATE INDEX IF NOT EXISTS paths_action ON paths(action_id);
CREATE INDEX IF NOT EXISTS paths_path ON paths(path);
CREATE INDEX IF NOT EXISTS hosts_action ON hosts(action_id);
CREATE INDEX IF NOT EXISTS hosts_host ON hosts(host);
"""

__all__ = ["COLUMNS", "SCHEMA"]
