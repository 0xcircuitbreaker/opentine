"""Shell tool — run subprocesses with timeout and optional allowlist."""

from __future__ import annotations

import subprocess


def run(command: str, timeout: int = 30, allowlist: list[str] | None = None) -> str:
    """Run a shell command and return stdout + stderr.

    If allowlist is provided, only commands starting with an allowed
    prefix will execute.
    """
    if allowlist:
        cmd_name = command.split()[0] if command.split() else ""
        if cmd_name not in allowlist:
            return f"Error: '{cmd_name}' not in allowlist {allowlist}"
    try:
        result = subprocess.run(
            command,
            shell=True,
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
