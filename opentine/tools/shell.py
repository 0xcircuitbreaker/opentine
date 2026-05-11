"""Shell tool: disabled by default and command-array based internally."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

from opentine.policies import ShellPolicy


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
        parts = shlex.split(command, posix=(sys.platform != "win32"))
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
        result = subprocess.run(
            parts,
            shell=False,
            capture_output=True,
            text=True,
            timeout=pol.timeout_seconds,
            cwd=str(Path.cwd()),
            env=_clean_env(pol),
        )
        output = result.stdout
        if result.stderr:
            output += f"\nSTDERR:\n{result.stderr}"
        if len(output) > pol.max_output_chars:
            output = output[: pol.max_output_chars - 14] + "... (truncated)"
        return output.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Error: command timed out after {pol.timeout_seconds}s"
    except Exception as e:
        return f"Error: {e}"
