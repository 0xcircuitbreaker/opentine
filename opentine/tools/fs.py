"""Filesystem tools — read, write, edit, list. Sandboxed to cwd by default."""

from __future__ import annotations

import os
from pathlib import Path


def _resolve(path: str, sandbox: str | None = None) -> Path:
    """Resolve path within sandbox. Raises ValueError if it escapes."""
    base = Path(sandbox or os.getcwd()).resolve()
    resolved = (base / path).resolve()
    if not str(resolved).startswith(str(base)):
        raise ValueError(f"Path {path} escapes sandbox {base}")
    return resolved


def read(path: str, sandbox: str | None = None) -> str:
    """Read a file and return its contents."""
    return _resolve(path, sandbox).read_text(encoding="utf-8")


def write(path: str, content: str, sandbox: str | None = None) -> str:
    """Write content to a file. Creates parent directories if needed."""
    p = _resolve(path, sandbox)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return f"Wrote {len(content)} chars to {path}"


def edit(path: str, old: str, new: str, sandbox: str | None = None) -> str:
    """Replace the first occurrence of `old` with `new` in a file."""
    p = _resolve(path, sandbox)
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise ValueError(f"String not found in {path}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")
    return f"Edited {path}"


def ls(path: str = ".", sandbox: str | None = None) -> str:
    """List directory contents."""
    p = _resolve(path, sandbox)
    entries = sorted(p.iterdir(), key=lambda e: (not e.is_dir(), e.name))
    lines = []
    for e in entries:
        prefix = "d " if e.is_dir() else "f "
        lines.append(f"{prefix}{e.name}")
    return "\n".join(lines) if lines else "(empty)"
