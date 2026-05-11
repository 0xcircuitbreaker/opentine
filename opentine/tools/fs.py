"""Filesystem tools with sandbox-root enforcement."""

from __future__ import annotations

import os
from pathlib import Path

from opentine.policies import FilesystemPolicy


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _policy(sandbox: str | None = None, policy: FilesystemPolicy | None = None) -> FilesystemPolicy:
    if policy:
        return policy
    return FilesystemPolicy(roots=(sandbox or os.getcwd(),), write_roots=(sandbox or os.getcwd(),))


def _resolve(
    path: str,
    sandbox: str | None = None,
    policy: FilesystemPolicy | None = None,
    *,
    write: bool = False,
) -> Path:
    """Resolve path within sandbox. Raises ValueError if it escapes."""
    pol = _policy(sandbox, policy)
    roots = tuple(Path(root).resolve() for root in (pol.write_roots if write else pol.roots))
    if not roots:
        raise PermissionError("No filesystem roots are allowed by policy")
    candidate = Path(path)
    raw = candidate if candidate.is_absolute() else roots[0] / candidate
    if pol.deny_symlinks:
        probe = raw
        for existing in [probe, *probe.parents]:
            if existing.exists() and existing.is_symlink():
                raise PermissionError(f"Symlink denied by policy: {existing}")
    resolved = raw.resolve(strict=False)
    if not any(_within(resolved, root) for root in roots):
        raise ValueError(f"Path {path} escapes sandbox roots")
    return resolved


def read(path: str, sandbox: str | None = None, policy: FilesystemPolicy | None = None) -> str:
    """Read a file and return its contents."""
    pol = _policy(sandbox, policy)
    p = _resolve(path, sandbox, pol)
    if p.stat().st_size > pol.max_file_bytes:
        raise ValueError(f"File exceeds max_file_bytes={pol.max_file_bytes}")
    return p.read_text(encoding="utf-8")


def write(
    path: str,
    content: str,
    sandbox: str | None = None,
    policy: FilesystemPolicy | None = None,
) -> str:
    """Write content to a file. Creates parent directories if needed."""
    pol = _policy(sandbox, policy)
    if len(content.encode("utf-8")) > pol.max_file_bytes:
        raise ValueError(f"Content exceeds max_file_bytes={pol.max_file_bytes}")
    p = _resolve(path, sandbox, pol, write=True)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return f"Wrote {len(content)} chars to {path}"


def edit(
    path: str,
    old: str,
    new: str,
    sandbox: str | None = None,
    policy: FilesystemPolicy | None = None,
) -> str:
    """Replace the first occurrence of `old` with `new` in a file."""
    pol = _policy(sandbox, policy)
    p = _resolve(path, sandbox, pol, write=True)
    if p.stat().st_size > pol.max_file_bytes:
        raise ValueError(f"File exceeds max_file_bytes={pol.max_file_bytes}")
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise ValueError(f"String not found in {path}")
    if len(text.replace(old, new, 1).encode("utf-8")) > pol.max_file_bytes:
        raise ValueError(f"Edited content exceeds max_file_bytes={pol.max_file_bytes}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")
    return f"Edited {path}"


def ls(path: str = ".", sandbox: str | None = None, policy: FilesystemPolicy | None = None) -> str:
    """List directory contents."""
    p = _resolve(path, sandbox, policy)
    entries = sorted(p.iterdir(), key=lambda e: (not e.is_dir(), e.name))
    lines = []
    for e in entries:
        prefix = "d " if e.is_dir() else "f "
        lines.append(f"{prefix}{e.name}")
    return "\n".join(lines) if lines else "(empty)"
