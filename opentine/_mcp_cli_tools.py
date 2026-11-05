"""MCP tools generated from :data:`opentine._mcp_registry.CLI_TOOLS`.

Each tool builds the ``tine`` argv its registry entry names, runs it in process
with ``--json`` and returns the parsed payload -- the same bytes the command
prints, so the tool cannot drift from the CLI. Arguments come from a model
reading untrusted run content: each is type-checked and bounded, and a value
that looks like an option is refused, so it can only ever fill its own slot.
"""

from __future__ import annotations

import contextlib
import inspect
import io
import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._mcp_registry import CLI_TOOLS, Param, ToolSpec

MAX_MCP_ARG_CHARS = 1024
MAX_MCP_LIMIT = 1_000
#: One CLI invocation at a time: it swaps ``sys.stdout`` and the runs directory.
_LOCK = threading.Lock()


def _value(param: Param, value: Any) -> str | None:
    if value is None:
        if param.required:
            raise ValueError(f"{param.name} is required")
        return None
    if param.kind is int:
        if type(value) is not int or not 1 <= value <= MAX_MCP_LIMIT:
            raise ValueError(f"{param.name} must be an integer from 1 to {MAX_MCP_LIMIT}")
        return str(value)
    if not isinstance(value, str) or not 0 < len(value) <= MAX_MCP_ARG_CHARS:
        raise ValueError(f"{param.name} must be 1 to {MAX_MCP_ARG_CHARS} characters")
    if value.startswith("-") or "\0" in value:
        raise ValueError(f"{param.name} may not start with '-' or hold a NUL")
    return value


def cli_argv(spec: ToolSpec, repo_path: str | Path, **arguments: Any) -> list[str]:
    """The ``tine`` argv a generated tool runs for *arguments*."""
    argv = list(spec.argv)
    for param in spec.params:
        text = _value(param, arguments.get(param.name, param.default))
        if text is not None:
            argv += [param.flag, text] if param.flag else [text]
    argv += list(spec.extra)
    if spec.repo:
        argv += ["--repo", str(repo_path)]
    return [*argv, "--json"]


def run_cli_json(argv: list[str], runs_dir: str | Path) -> Any:
    """Run ``tine ARGV`` in process; its JSON payload (a list for NDJSON output)."""
    from opentine import cli

    out, err, code = io.StringIO(), io.StringIO(), 0
    with _LOCK:
        saved, cli.RUNS_DIR = cli.RUNS_DIR, Path(runs_dir)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                cli.main(argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
        finally:
            cli.RUNS_DIR = saved
    text = out.getvalue()
    try:
        payload = json.loads(text)
    except ValueError:
        lines = [line for line in text.splitlines() if line.strip()]
        try:
            payload = [json.loads(line) for line in lines]
        except ValueError:
            payload = None
    if code and not isinstance(payload, dict):  # a --json failure keeps its payload
        message = (err.getvalue() or text).strip().splitlines()
        raise ValueError(message[-1] if message else f"tine {argv[0]} exited {code}")
    if payload is None or payload == []:
        raise ValueError(f"tine {argv[0]} printed no JSON")
    return payload


def _tool(spec: ToolSpec, runs_dir: str | Path, repo_path: str | Path) -> Callable[..., Any]:
    def tool(**arguments: Any) -> Any:
        return run_cli_json(cli_argv(spec, repo_path, **arguments), runs_dir)

    parameters = [
        inspect.Parameter(
            param.name,
            inspect.Parameter.KEYWORD_ONLY,
            default=inspect.Parameter.empty if param.required else param.default,
            annotation=param.kind if param.required else param.kind | None,
        )
        for param in spec.params
    ]
    tool.__name__ = tool.__qualname__ = spec.name
    tool.__doc__ = spec.doc
    tool.__signature__ = inspect.Signature(parameters, return_annotation=Any)  # type: ignore[attr-defined]
    tool.__annotations__ = {p.name: p.annotation for p in parameters} | {"return": Any}
    return tool


def register_cli_tools(mcp: Any, runs_dir: str | Path, repo_path: str | Path) -> None:
    """Register every generated tool; the server's proxy decides which are exposed."""
    from opentine._mcp_safety import safe_errors

    mcp = safe_errors(mcp)
    for spec in CLI_TOOLS:
        mcp.tool()(_tool(spec, runs_dir, repo_path))


__all__ = ["cli_argv", "register_cli_tools", "run_cli_json"]
