"""Python execution tool — runs code in a subprocess for real isolation."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from opentine.policies import PythonPolicy

_SENSITIVE_PAT = re.compile(r"(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)", re.IGNORECASE)


def _clean_env(policy: PythonPolicy) -> dict[str, str]:
    """Return a copy of the environment with sensitive variables removed."""
    if policy.inherit_env:
        return {k: v for k, v in os.environ.items() if not _SENSITIVE_PAT.search(k)}
    return {name: os.environ[name] for name in policy.env_allowlist if name in os.environ}


def execute(code: str, timeout: int = 30, policy: PythonPolicy | None = None) -> str:
    """Execute Python code in an isolated subprocess and return the output."""
    pol = policy or PythonPolicy(enabled=False, timeout_seconds=timeout)
    if not pol.enabled:
        return "Error: Python execution disabled by policy"
    try:
        with tempfile.TemporaryDirectory(prefix="opentine-python-") as tmp:
            script_path = str(Path(tmp) / "snippet.py")
            Path(script_path).write_text(code, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, script_path],
                capture_output=True,
                text=True,
                timeout=pol.timeout_seconds,
                env=_clean_env(pol),
                cwd=tmp,
            )
            output = result.stdout
            if result.stderr:
                output += f"\nSTDERR:\n{result.stderr}"
            if len(output) > pol.max_output_chars:
                output = output[: pol.max_output_chars - 14] + "... (truncated)"
            return output.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Error: execution timed out after {pol.timeout_seconds}s"
    except Exception as e:
        return f"Error: {e}"


def execute_unsafe_legacy(code: str, timeout: int = 30) -> str:
    """Compatibility escape hatch for callers that deliberately opt out."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(code)
        script_path = f.name
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_clean_env(PythonPolicy(enabled=True, inherit_env=True)),
        )
        output = result.stdout
        if result.stderr:
            output += f"\nSTDERR:\n{result.stderr}"
        return output.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Error: execution timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"
    finally:
        Path(script_path).unlink(missing_ok=True)
