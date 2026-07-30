"""Python execution tool — runs code in a subprocess for real isolation."""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

from opentine.policies import PythonPolicy
from opentine.tools._process import run_bounded

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
            # newline="" keeps model-authored code byte-faithful: the default
            # translates "\n" to os.linesep, corrupting CRLF (-> \r\r\n) inside
            # string literals on Windows.
            with Path(script_path).open("w", encoding="utf-8", newline="") as handle:
                handle.write(code)
            result = run_bounded(
                [sys.executable, script_path],
                timeout=pol.timeout_seconds,
                max_chars=pol.max_output_chars,
                env=_clean_env(pol),
                cwd=tmp,
            )
            if result.timed_out:
                return result.output(
                    pol.max_output_chars,
                    prefix=f"Error: execution timed out after {pol.timeout_seconds}s\n",
                )
            return result.output(pol.max_output_chars)
    except Exception as e:
        return f"Error: {e}"


def execute_unsafe_legacy(code: str, timeout: int = 30) -> str:
    """Compatibility escape hatch for callers that deliberately opt out."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8", newline=""
    ) as f:
        f.write(code)
        script_path = f.name
    try:
        result = run_bounded(
            [sys.executable, script_path],
            timeout=timeout,
            max_chars=8_000,
            env=_clean_env(PythonPolicy(enabled=True, inherit_env=True)),
        )
        if result.timed_out:
            return result.output(8_000, prefix=f"Error: execution timed out after {timeout}s\n")
        return result.output(8_000)
    except Exception as e:
        return f"Error: {e}"
    finally:
        Path(script_path).unlink(missing_ok=True)


# Policy and resource ceilings belong to the host, not to model-generated calls.
execute.__opentine_hidden_parameters__ = frozenset({"timeout", "policy"})
