"""Shell tool: disabled by default and command-array based internally."""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

from opentine.policies import ShellPolicy
from opentine.tools._process import run_bounded


def _strip_outer_quotes(part: str) -> str:
    if len(part) >= 2 and part[0] == part[-1] and part[0] in {"'", '"'}:
        return part[1:-1]
    return part


def _split_command(command: str) -> list[str]:
    parts = shlex.split(command, posix=(sys.platform != "win32"))
    if sys.platform == "win32":
        parts = [_strip_outer_quotes(part) for part in parts]
    return parts


def _subprocess_parts(parts: list[str]) -> list[str]:
    if sys.platform == "win32" and parts[0] in {"python", "python3"}:
        return [sys.executable, *parts[1:]]
    return parts


def _clean_env(policy: ShellPolicy) -> dict[str, str]:
    if policy.inherit_env:
        return dict(os.environ)
    return {name: os.environ[name] for name in policy.env_allowlist if name in os.environ}


def run(
    command: str,
    timeout: int = 30,
    allowlist: list[str] | None = None,
    sandbox: bool = True,
    policy: ShellPolicy | None = None,
) -> str:
    """Run a shell command and return stdout + stderr.

    If sandbox is True (the default), an allowlist must be provided and the
    executable (first token) must be in that list.  Set sandbox=False to
    allow arbitrary commands (use with caution).
    """
    try:
        parts = _split_command(command)
    except ValueError as e:
        return f"Error: failed to parse command: {e}"

    if not parts:
        return "Error: empty command"

    executable = parts[0]

    pol = policy or ShellPolicy(
        enabled=not sandbox,
        executables=tuple(allowlist or ()),
        timeout_seconds=timeout,
    )
    if not pol.enabled:
        return "Error: shell execution disabled by policy"
    if pol.executables and executable not in pol.executables:
        return f"Error: '{executable}' not in allowlist {list(pol.executables)}"

    cwd_root = Path(pol.cwd_root).resolve()
    try:
        Path.cwd().resolve().relative_to(cwd_root)
    except ValueError:
        return f"Error: cwd escapes shell policy root {cwd_root}"

    try:
        result = run_bounded(
            _subprocess_parts(parts),
            timeout=pol.timeout_seconds,
            max_chars=pol.max_output_chars,
            cwd=str(Path.cwd()),
            env=_clean_env(pol),
        )
        if result.timed_out:
            return result.output(
                pol.max_output_chars,
                prefix=f"Error: command timed out after {pol.timeout_seconds}s\n",
            )
        return result.output(pol.max_output_chars)
    except Exception as e:
        return f"Error: {e}"
