"""Safe code and environment manifests for reproducible run starts."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any


def _git(cwd: Path, *arguments: str) -> tuple[str, str | None]:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout, None
    except (OSError, subprocess.SubprocessError) as exc:
        return "", f"{type(exc).__name__}: {exc}"


def code_manifest(path: str | Path = ".") -> dict[str, Any]:
    root = Path(path).resolve()
    commit_raw, commit_error = _git(root, "rev-parse", "HEAD")
    patch, patch_error = _git(root, "diff", "--binary", "--no-ext-diff")
    staged, staged_error = _git(root, "diff", "--binary", "--cached", "--no-ext-diff")
    errors = {
        name: error
        for name, error in {
            "commit": commit_error,
            "patch": patch_error,
            "staged_patch": staged_error,
        }.items()
        if error
    }
    commit = commit_raw.strip()
    return {
        "capture_complete": not errors,
        "capture_errors": errors,
        "commit": commit or None,
        "dirty": bool(patch or staged),
        "patch": patch,
        "staged_patch": staged,
        "worktree": str(root),
    }


def environment_manifest() -> dict[str, Any]:
    return {
        "executable": sys.executable,
        "implementation": platform.python_implementation(),
        "machine": platform.machine(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "selected_env": {
            name: os.environ[name] for name in ("CI", "LANG", "TZ") if name in os.environ
        },
    }
