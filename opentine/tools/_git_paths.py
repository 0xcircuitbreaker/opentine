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
"""

from __future__ import annotations

import re
from collections.abc import Callable

from opentine.tools._git_tree import whole_tree_refusal

#: Commands for which ``rev:path`` reads committed content and changes nothing.
_REV_PATH_READERS = frozenset({"show", "diff", "log", "grep", "blame"})

_DRIVE = re.compile(r"^[A-Za-z]:")


def pathspec_refusal(
    subcommand: str, positionals: list[str], contained: Callable[[str], bool]
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
            if not rev or path.startswith(("/", "\\")) or (path and not contained(path)):
                return f"git {subcommand} rev:path {token[:40]!r} is not allowed"
        if not contained(token):
            return f"git {subcommand} path {token[:40]!r} must stay inside the shell root"
    return None


__all__ = ["pathspec_refusal", "whole_tree_refusal"]
