"""Shell tool — run subprocesses with timeout and optional allowlist."""

from __future__ import annotations

import shlex
import subprocess
import sys


def run(
    command: str,
    timeout: int = 30,
    allowlist: list[str] | None = None,
    sandbox: bool = True,
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

    if sandbox:
        if not allowlist:
            return "Error: sandbox is enabled but no allowlist was provided"
        if executable not in allowlist:
            return f"Error: '{executable}' not in allowlist {allowlist}"

    try:
        result = subprocess.run(
            parts,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout
        if result.stderr:
            output += f"\nSTDERR:\n{result.stderr}"
        return output.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Error: command timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"
