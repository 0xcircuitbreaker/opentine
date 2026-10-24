"""Containment for the pathspecs and paths git's ordinary subcommands are given.

``git rm -r ../``, ``git checkout HEAD -- ../file`` or ``git add ':(top)'``
act on files outside the shell root whenever the root is a subdirectory of a
larger repository: git resolves a pathspec against the repository, not the
shell root. Every positional of a local subcommand is therefore taken as a
path relative to git's working directory and must stay inside the root.

Revision names (``HEAD~1``, ``main``, ``a..b``) are single relative path
components and pass this check unchanged. Pathspec magic (a leading ``:``,
including ``:/`` and ``:(top)``) is refused outright; ``rev:path`` is accepted
only by the read-only commands, where it names committed content rather than
a file to change -- and even then the whole token must also be contained as a
filesystem path: ``git diff`` silently switches to ``--no-index`` when a path
lies outside the work tree, so ``a:b/../../x`` would otherwise read host files.
Drive letters, backslashes and an absolute path after the colon are refused.

Git resolves the path of ``rev:path`` against the *repository top*, not the
working directory, unless it starts with ``./`` or ``../``. When the shell root
is a subdirectory, ``HEAD:secret`` (or ``HEAD:`` for the whole top tree) names
committed content above the root, so such a path is also checked as resolved
from the repository top.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from opentine.tools._git_tree import repository_top, whole_tree_refusal

#: Commands for which ``rev:path`` reads committed content and changes nothing.
_REV_PATH_READERS = frozenset({"show", "diff", "log", "grep", "blame"})

_DRIVE = re.compile(r"^[A-Za-z]:")


def _from_top(path: str, where: tuple[Path, Path] | None) -> bool:
    """Whether *path* of ``rev:path``, as git resolves it, stays inside the root."""
    if path == "." or path == ".." or path.startswith(("./", "../")) or where is None:
        return True  # cwd-relative: the ordinary containment check covers it
    root, cwd = where
    top = repository_top(cwd) or cwd
    try:
        (top / path).resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def pathspec_refusal(
    subcommand: str,
    positionals: list[str],
    contained: Callable[[str], bool],
    where: tuple[Path, Path] | None = None,
) -> str | None:
    """Why a positional of *subcommand* reaches outside the shell root, or None."""
    for token in positionals:
        if not token:
            continue
        if token.startswith(":"):
            return f"git {subcommand} pathspec magic {token[:12]!r} is not allowed"
        if "\\" in token or _DRIVE.match(token):
            return f"git {subcommand} path {token[:40]!r} is not allowed"
        if ":" in token:
            if subcommand not in _REV_PATH_READERS:
                return f"git {subcommand} path {token[:40]!r} must stay inside the shell root"
            rev, _, path = token.partition(":")
            if (
                not rev
                or path.startswith(("/", "\\"))
                or (path and not contained(path))
                or not _from_top(path, where)
            ):
                return f"git {subcommand} rev:path {token[:40]!r} is not allowed"
        if not contained(token):
            return f"git {subcommand} path {token[:40]!r} must stay inside the shell root"
    return None


__all__ = ["pathspec_refusal", "whole_tree_refusal"]
