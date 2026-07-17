"""Safe code and environment manifests for reproducible run starts."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from opentine.tools._process import run_bounded

MAX_GIT_CAPTURE_BYTES = 16 * 1024 * 1024
MAX_STATUS_ENTRIES = 10_000


def _git(cwd: Path, *arguments: str) -> tuple[str, str | None]:
    try:
        result = run_bounded(
            ["git", *arguments],
            cwd=str(cwd),
            timeout=30,
            max_chars=4_000,
            max_bytes=MAX_GIT_CAPTURE_BYTES,
        )
        command = "git " + " ".join(arguments)
        if result.timed_out:
            return "", f"TimeoutExpired: {command} exceeded 30 seconds"
        if result.returncode:
            details = result.stderr.decode(errors="replace").strip()[-1_000:]
            return "", f"git exited {result.returncode}: {details or command}"
        if result.stdout_truncated:
            return "", f"git output exceeds {MAX_GIT_CAPTURE_BYTES} bytes: {command}"
        return result.stdout.decode(errors="replace"), None
    except (OSError, subprocess.SubprocessError) as exc:
        return "", f"{type(exc).__name__}: {exc}"


def code_manifest(path: str | Path = ".") -> dict[str, Any]:
    root = Path(path).resolve()
    commit_raw, commit_error = _git(root, "rev-parse", "HEAD")
    patch, patch_error = _git(root, "diff", "--binary", "--no-ext-diff", "--no-textconv")
    staged, staged_error = _git(
        root, "diff", "--binary", "--cached", "--no-ext-diff", "--no-textconv"
    )
    status, status_error = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    records = status.split("\0", MAX_STATUS_ENTRIES + 1)
    if records and not records[-1]:
        records.pop()
    status_overflow = len(records) > MAX_STATUS_ENTRIES
    if status_overflow:
        records = records[:MAX_STATUS_ENTRIES]
    untracked = sorted(record[3:] for record in records if record.startswith("?? "))
    errors = {
        name: error
        for name, error in {
            "commit": commit_error,
            "patch": patch_error,
            "staged_patch": staged_error,
            "status": status_error,
            "status_entries": "status entry limit exceeded" if status_overflow else None,
            "untracked": (
                f"{len(untracked)} untracked paths are listed but their contents are not captured"
                if untracked
                else None
            ),
        }.items()
        if error
    }
    commit = commit_raw.strip()
    return {
        "capture_complete": not errors,
        "capture_errors": errors,
        "commit": commit or None,
        "dirty": bool(patch or staged or status or patch_error or staged_error or status_error),
        "patch": patch,
        "staged_patch": staged,
        "untracked_files": untracked,
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
