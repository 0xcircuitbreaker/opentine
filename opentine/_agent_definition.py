"""The ``definition_digest`` of an agent: a hash of the files that define it.

The digest covers each file's path (relative, POSIX) and its bytes with CRLF
folded to LF, so one definition hashes the same on Windows and POSIX. Only the
digest is ever recorded -- never the content, which can hold secrets.

The digest proves which files were hashed, not that the agent obeyed them.
Paths must stay inside *root*: absolute paths, ``..`` and symlinks are refused,
and file count and size are bounded.
"""

from __future__ import annotations

import hashlib
import stat
from collections.abc import Iterable
from pathlib import Path

DOMAIN = b"opentine.agent-definition.v1\0"
MAX_FILES = 64
MAX_FILE_BYTES = 1 << 20

#: Files that define an agent for each known harness, relative to its root.
HARNESS_FILES: dict[str, tuple[str, ...]] = {
    "claude-code": ("CLAUDE.md", ".mcp.json", ".claude/agents/*.md"),
    "codex": ("AGENTS.md", ".codex/config.toml"),
    "gemini": ("GEMINI.md", ".gemini/settings.json"),
    "opencode": ("AGENTS.md", "opencode.json"),
}


class DefinitionError(ValueError):
    pass


def _inside(root: Path, path: Path) -> str:
    candidate = path if path.is_absolute() else root / path
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise DefinitionError(f"definition file {str(path)!r} is outside {root}") from exc
    if ".." in relative.parts or not relative.parts:
        raise DefinitionError(f"definition file {str(path)!r} escapes its root")
    walk = root
    for part in relative.parts:
        walk = walk / part
        if walk.is_symlink():
            raise DefinitionError(f"definition file {relative.as_posix()!r} is a link")
    return relative.as_posix()


def _read(path: Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise DefinitionError(f"definition file {path.name!r} is not a regular file")
    with path.open("rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise DefinitionError(f"definition file {path.name!r} exceeds {MAX_FILE_BYTES} bytes")
    return data.replace(b"\r\n", b"\n")


def definition_digest(paths: Iterable[str | Path], root: str | Path = ".") -> str:
    """``sha256:<hex>`` over *paths* (relative to *root*), or ``""`` for none."""
    base = Path(root).absolute()
    named = {_inside(base, Path(item)) for item in paths}
    if not named:
        return ""
    if len(named) > MAX_FILES:
        raise DefinitionError(f"more than {MAX_FILES} definition files")
    digest = hashlib.sha256(DOMAIN)
    for relative in sorted(named):
        body = hashlib.sha256(_read(base / relative)).hexdigest()
        digest.update(f"{relative}\0{body}\n".encode())
    return "sha256:" + digest.hexdigest()


def harness_files(harness: str, root: str | Path = ".") -> list[str]:
    """The known definition files of *harness* that exist under *root*."""
    base = Path(root)
    found: list[str] = []
    for pattern in HARNESS_FILES.get(harness, ()):
        for match in sorted(base.glob(pattern))[:MAX_FILES]:
            if match.is_file() and not match.is_symlink():
                found.append(match.relative_to(base).as_posix())
    return found[:MAX_FILES]


def harness_digest(harness: str, root: str | Path = ".") -> str:
    """The digest of *harness*'s definition files under *root*; ``""`` if unreadable."""
    try:
        return definition_digest(harness_files(harness, root), root)
    except (DefinitionError, OSError):
        return ""


__all__ = [
    "HARNESS_FILES",
    "DefinitionError",
    "definition_digest",
    "harness_digest",
    "harness_files",
]
