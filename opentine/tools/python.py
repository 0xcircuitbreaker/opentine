"""Python execution tool — runs code in a subprocess for real isolation."""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


def execute(code: str, timeout: int = 30) -> str:
    """Execute Python code in an isolated subprocess and return the output."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(code)
        script_path = f.name
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True, text=True, timeout=timeout,
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
