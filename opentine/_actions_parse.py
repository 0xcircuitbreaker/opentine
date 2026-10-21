"""Classify a recorded tool call: verb, command, paths and hosts.

Everything here reads *redacted* tool arguments (see :mod:`opentine._actions`)
and is linear in its input: no regex here can backtrack, every list is capped,
and a command longer than :data:`MAX_COMMAND_CHARS` is clipped and flagged.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

MAX_COMMAND_CHARS = 8_192
MAX_FIELD_CHARS = 1_024

#: Tool names (lowercased, ``-``/space folded to ``_``) per verb. A name not
#: listed is classified from its arguments: a ``command`` makes it ``exec``.
_VERBS: dict[str, frozenset[str]] = {
    "exec": frozenset(
        "bash shell sh zsh exec execute run_shell_command local_shell shell_command "
        "run_command execute_command command terminal powershell cmd run_terminal_cmd".split()
    ),
    "file.read": frozenset(
        "read read_file view view_file cat file_read open_file grep glob ls list_dir "
        "list_directory search_files find_files read_many_files".split()
    ),
    "file.write": frozenset(
        "write write_file edit multiedit multi_edit str_replace str_replace_editor "
        "str_replace_based_edit_tool apply_patch patch create_file edit_file file_write "
        "notebookedit notebook_edit replace insert file_change".split()
    ),
    "file.delete": frozenset("delete delete_file remove remove_file rm unlink".split()),
    "net": frozenset(
        "webfetch web_fetch fetch http http_request web_search websearch browser "
        "browse google_search search_web url_fetch download".split()
    ),
    "spawn_subagent": frozenset("task agent spawn_agent subagent dispatch_agent".split()),
}
_DELETE_ARGV0 = frozenset({"rm", "rmdir", "unlink", "shred"})
_WRAPPERS = frozenset({"sudo", "env", "nohup", "time", "nice", "timeout", "doas", "command"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "pwsh", "powershell"})
_COMMAND_KEYS = ("command", "cmd", "commands", "script", "input", "code")


def tool_key(name: str) -> str:
    return re.sub(r"[\s-]+", "_", name.strip().lower())[:MAX_FIELD_CHARS]


def mcp_parts(name: str, arguments: Any) -> tuple[str, str]:
    """``(server, tool)`` for an MCP call, or ``("", "")``."""
    if name.startswith("mcp__"):
        server, _, tool = name[5:].partition("__")
        return server[:MAX_FIELD_CHARS], tool[:MAX_FIELD_CHARS]
    if isinstance(arguments, dict) and isinstance(arguments.get("server"), str):
        tool = arguments.get("tool") or arguments.get("name") or name
        return arguments["server"][:MAX_FIELD_CHARS], str(tool)[:MAX_FIELD_CHARS]
    return "", ""


def command_text(arguments: Any) -> str | None:
    """The shell command a tool call ran, as one string, or None."""
    if isinstance(arguments, str):
        return None
    if not isinstance(arguments, dict):
        return None
    for key in _COMMAND_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, list) and value and all(isinstance(part, str) for part in value):
            return shlex.join(value[:4096])
    return None


def _tokens(command: str) -> list[str]:
    """Shell words, with ``;`` ``&&`` ``|`` ... as their own tokens even when unspaced."""
    lexer = shlex.shlex(command[:MAX_COMMAND_CHARS], posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    tokens: list[str] = []
    try:
        for token in lexer:
            tokens.append(token)
            if len(tokens) >= 4096:
                break
    except ValueError:
        return command[:MAX_COMMAND_CHARS].split()[:4096]
    return tokens


_ARG_FLAGS = frozenset({"-u", "-g", "-C", "-p", "-U", "-r", "-t", "-h", "-n", "-s", "-k"})
_OPERATORS = frozenset({"&&", "||", ";", "|", "&", "|&", ";;", "(", ")"})


def _program(tokens: list[str], depth: int = 0) -> str:
    """The program a token list starts, past ``sudo``/``env``/``sh -c`` wrappers."""
    index, wrapped = 0, False
    while index < len(tokens):
        token = tokens[index]
        base = token.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        if not wrapped and "=" in token and not token.startswith("-"):
            index += 1  # VAR=value prefix
        elif base in _WRAPPERS:
            index, wrapped = index + 1, True
        elif wrapped and token.startswith("-"):
            index += 2 if token in _ARG_FLAGS else 1
        elif wrapped and base[:1].isdigit():
            index += 1  # timeout DURATION
        elif base in _SHELLS:
            flag = tokens[index + 1] if index + 1 < len(tokens) else ""
            if flag.startswith("-") and not flag.startswith("--") and "c" in flag:
                inner = tokens[index + 2] if index + 2 < len(tokens) else ""
                return _program(_tokens(inner), depth + 1) if inner and depth < 4 else base
            return base
        else:
            return base.removesuffix(".exe")[:MAX_FIELD_CHARS]
    return ""


def programs(command: str) -> list[str]:
    """Every program a command line runs, one per ``&&``/``;``/``|`` segment (capped)."""
    found: dict[str, None] = {}
    segment: list[str] = []
    for token in [*_tokens(command), ";"]:
        if token in _OPERATORS:
            if segment and (name := _program(segment)):
                found.setdefault(name, None)
            segment = []
            if len(found) >= 32:
                break
        else:
            segment.append(token)
    return list(found)


def argv0(command: str) -> str:
    """The first program a command line runs."""
    found = programs(command)
    return found[0] if found else ""


def verbs(name: str, command: str | None, run: list[str]) -> list[str]:
    key = tool_key(name)
    found = [verb for verb, names in _VERBS.items() if key in names]
    if command is not None and not found:
        found.append("exec")
    if "git" in run:
        found.append("git")
    if _DELETE_ARGV0.intersection(run):
        found.append("file.delete")
    return found or ["other"]


__all__ = [
    "MAX_COMMAND_CHARS",
    "argv0",
    "command_text",
    "mcp_parts",
    "programs",
    "tool_key",
    "verbs",
]
