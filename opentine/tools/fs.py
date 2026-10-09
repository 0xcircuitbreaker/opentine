"""Filesystem tools with sandbox-root enforcement."""

from __future__ import annotations

import json
import os
from pathlib import Path

from opentine.policies import FilesystemPolicy
from opentine.tools._fs_open import list_entries, open_file

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
    return _locate(path, sandbox, policy, write=write)[1]


def _locate(
    path: str,
    sandbox: str | None = None,
    policy: FilesystemPolicy | None = None,
    *,
    write: bool = False,
) -> tuple[Path, Path]:
    """The root a path is inside, and the path resolved within it."""
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
    inside = [root for root in roots if _within(resolved, root)]
    if not inside:
        raise ValueError(f"Path {path} escapes sandbox roots")
    if write:
        _refuse_unsafe_write(path, raw, resolved)
    return inside[0], resolved


def _refuse_unsafe_write(path: str, raw: Path, resolved: Path) -> None:
    """Refuse a write git would later execute, or one that lands outside the root.

    A model that could write ``.git/config`` (``core.fsmonitor``, a filter
    driver) or ``.git/hooks`` ran its command on the host the next time git ran
    in the workspace -- including ``code_manifest`` capturing it after the run.
    Any ``.git`` component is refused, case-insensitively for the file systems
    that fold case, and a ``.git`` *file* too (it redirects to another git
    directory). A hard-linked file is refused because writing it writes every
    other name for that inode, which need not be inside the sandbox.
    """
    if any(part.lower() == ".git" for part in (*raw.parts, *resolved.parts)):
        raise PermissionError(f"Writing inside a .git directory is denied by policy: {path}")
    try:
        links = resolved.lstat().st_nlink
    except FileNotFoundError:
        return
    if resolved.is_file() and links > 1:
        raise PermissionError(f"Writing a hard-linked file is denied by policy: {path}")


def _require_regular(path: Path) -> None:
    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {path}")


def read(path: str, sandbox: str | None = None, policy: FilesystemPolicy | None = None) -> str:
    """Read a file and return its contents."""
    pol = _policy(sandbox, policy)
    root, p = _locate(path, sandbox, pol)
    _require_regular(p)
    return _read_text(root, p, pol.max_file_bytes)


def _read_text(root: Path, path: Path, limit: int) -> str:
    # The checked path is the one opened (_fs_open), and the size is that file's.
    with os.fdopen(open_file(root, path), "rb") as handle:
        if os.fstat(handle.fileno()).st_size > limit:
            raise ValueError(f"File exceeds max_file_bytes={limit}")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"File exceeds max_file_bytes={limit}")
    # Undecoded newlines, to match edit(): universal-newline translation showed
    # agents "\n" for a CRLF file, so a multi-line `old` copied from read()
    # output could never match the raw content edit() compares against.
    return data.decode("utf-8")


def _write_text(root: Path, path: Path, text: str) -> None:
    # newline="" to match read()/edit(): the default translates "\n" to
    # os.linesep on write, so on Windows a read()->write() round trip turned
    # every CRLF into \r\r\n (compounding per trip) and the bytes on disk
    # could exceed the max_file_bytes budget checked above.
    with os.fdopen(open_file(root, path, write=True), "w", encoding="utf-8", newline="") as out:
        out.write(text)


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
    root, p = _locate(path, sandbox, pol, write=True)
    if p.exists():
        _require_regular(p)
    _write_text(root, p, content)
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
    root, p = _locate(path, sandbox, pol, write=True)
    _require_regular(p)
    # Untranslated line endings on both sides: the default translates every one
    # on read and again on write, so editing one line silently rewrote every
    # other line in the file and turned a one-line change into a whole-file diff.
    text = _read_text(root, p, pol.max_file_bytes)
    if old not in text:
        raise ValueError(f"String not found in {path}")
    if len(text.replace(old, new, 1).encode("utf-8")) > pol.max_file_bytes:
        raise ValueError(f"Edited content exceeds max_file_bytes={pol.max_file_bytes}")
    _write_text(root, p, text.replace(old, new, 1))
    return f"Edited {path}"


def ls(path: str = ".", sandbox: str | None = None, policy: FilesystemPolicy | None = None) -> str:
    """List directory contents."""
    root, p = _locate(path, sandbox, policy)
    if not p.is_dir():
        missing = FileNotFoundError if not p.exists() else NotADirectoryError
        raise missing(f"Not a directory: {path}")
    entries = list_entries(root, p, MAX_LIST_ENTRIES)
    truncated = len(entries) > MAX_LIST_ENTRIES
    entries = sorted(entries[:MAX_LIST_ENTRIES], key=lambda e: (not e[0], e[1]))
    lines = []
    for is_dir, name in entries:
        prefix = "d " if is_dir else "f "
        escaped = json.dumps(name, ensure_ascii=True)[1:-1]
        lines.append(f"{prefix}{escaped}")
    if truncated:
        lines.append(f"... (truncated after {MAX_LIST_ENTRIES} entries)")
    return "\n".join(lines) if lines else "(empty)"


# Security policy objects and compatibility sandbox roots are host configuration,
# never model-controlled tool arguments. Agent rejects hidden arguments at runtime.
for _function in (read, write, edit, ls):
    _function.__opentine_hidden_parameters__ = frozenset({"sandbox", "policy"})
