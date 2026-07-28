"""Filesystem tools with sandbox-root enforcement."""

from __future__ import annotations

import json
import os
from itertools import islice
from pathlib import Path

from opentine.policies import FilesystemPolicy

MAX_LIST_ENTRIES = 1_000


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _policy(sandbox: str | None = None, policy: FilesystemPolicy | None = None) -> FilesystemPolicy:
    if policy:
        return policy
    root = sandbox or os.getcwd()
    return FilesystemPolicy(roots=(root,), write_roots=(root,) if sandbox is not None else ())


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


def _require_regular(path: Path) -> None:
    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {path}")


def read(path: str, sandbox: str | None = None, policy: FilesystemPolicy | None = None) -> str:
    """Read a file and return its contents."""
    pol = _policy(sandbox, policy)
    p = _resolve(path, sandbox, pol)
    _require_regular(p)
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
    if p.exists():
        _require_regular(p)
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
    _require_regular(p)
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
    entries = list(islice(p.iterdir(), MAX_LIST_ENTRIES + 1))
    truncated = len(entries) > MAX_LIST_ENTRIES
    entries = sorted(entries[:MAX_LIST_ENTRIES], key=lambda e: (not e.is_dir(), e.name))
    lines = []
    for e in entries:
        prefix = "d " if e.is_dir() else "f "
        escaped = json.dumps(e.name, ensure_ascii=True)[1:-1]
        lines.append(f"{prefix}{escaped}")
    if truncated:
        lines.append(f"... (truncated after {MAX_LIST_ENTRIES} entries)")
    return "\n".join(lines) if lines else "(empty)"


# Security policy objects and compatibility sandbox roots are host configuration,
# never model-controlled tool arguments. Agent rejects hidden arguments at runtime.
for _function in (read, write, edit, ls):
    _function.__opentine_hidden_parameters__ = frozenset({"sandbox", "policy"})
