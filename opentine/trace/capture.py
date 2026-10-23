"""Safe code and environment manifests for reproducible run starts."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from opentine import _tineignore as tineignore
from opentine.tools._git_guard import HARDENED_CONFIG, git_env
from opentine.tools._process import run_bounded

MAX_GIT_CAPTURE_BYTES = 16 * 1024 * 1024
MAX_STATUS_ENTRIES = 10_000


def _git(cwd: Path, *arguments: str) -> tuple[str, str | None]:
    try:
        result = run_bounded(
            ["git", *HARDENED_CONFIG, *arguments],
            cwd=str(cwd),
            env=git_env(os.environ),
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
    # Unquoted paths in diff headers, so .tineignore can match non-ASCII names;
    # paths with quotes, backslashes or controls stay C-quoted and are unquoted.
    plain = ("-c", "core.quotePath=false", "diff", "--binary", "--no-ext-diff", "--no-textconv")
    patch, patch_error = _git(root, *plain)
    staged, staged_error = _git(root, *plain, "--cached")
    status, status_error = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    records = status.split("\0", MAX_STATUS_ENTRIES + 1)
    if records and not records[-1]:
        records.pop()
    status_overflow = len(records) > MAX_STATUS_ENTRIES
    if status_overflow:
        records = records[:MAX_STATUS_ENTRIES]
    untracked = sorted(record[3:] for record in records if record.startswith("?? "))
    # .tineignore: excluded paths never enter the capture, redacted ones keep
    # their name but lose their hunks. Applied before `dirty` and the errors.
    # .tineignore lives at the worktree root, and git reports paths relative to
    # it, so a capture started from a subdirectory must load the root's rules.
    top, top_error = _git(root, "rev-parse", "--show-toplevel")
    try:
        if top_error and (patch or staged or untracked):
            raise OSError(f"worktree root unknown: {top_error}")
        rules = tineignore.load(Path(top.strip()) if top.strip() else root)
        ignore_error = None
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        # Fail closed: a broken .tineignore must not capture what it meant to hide.
        rules, ignore_error, patch, staged = None, f"{exc}; patches not captured", "", ""
    if rules:
        patch = tineignore.filter_patch(patch, rules)
        staged = tineignore.filter_patch(staged, rules)
        untracked = tineignore.filter_paths(untracked, rules)
    errors = {
        name: error
        for name, error in {
            "commit": commit_error,
            "patch": patch_error,
            "staged_patch": staged_error,
            "status": status_error,
            "tineignore": ignore_error,
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
