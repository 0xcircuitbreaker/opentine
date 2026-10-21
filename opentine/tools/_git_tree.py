"""Whole-tree git forms when the shell root is a subdirectory of a larger repository.

Containment checks the paths git is *told* to use. Some forms name no path and
act on the whole repository instead: ``reset --hard``, ``commit -a``,
``add -A``, ``stash``, ``merge``, ``pull``, or a ``checkout``/``switch`` of
another branch rewrite or discard files anywhere in the work tree. When the
shell root is the repository's top level (or contains it) that is still the
root; when the repository extends above the root, these forms reach files the
root was meant to fence off, so they are refused unless they name a contained
pathspec after ``--``.
"""

from __future__ import annotations

from pathlib import Path

_ALWAYS = frozenset({"merge", "pull", "switch"})
_STASH_READS = frozenset({"list", "show"})


def repository_top(start: Path) -> Path | None:
    """The nearest directory at or above *start* holding a ``.git`` entry."""
    try:
        here = start.resolve()
    except OSError:
        return None
    for candidate in (here, *here.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _extends_above(root: Path, cwd: Path) -> bool:
    top = repository_top(cwd)
    if top is None:
        return False
    try:
        top.relative_to(root.resolve())
    except ValueError:
        return True  # the repository's top lies above the shell root
    return False


def _flag(rest: list[str], longs: set[str], letters: str) -> bool:
    for token in rest:
        if token == "--":
            return False
        if token.split("=", 1)[0] in longs:
            return True
        if token.startswith("-") and not token.startswith("--"):
            if any(letter in token[1:] for letter in letters):
                return True
    return False


def _pathspec_after_dashes(rest: list[str]) -> bool:
    return "--" in rest and bool(rest[rest.index("--") + 1 :])


def whole_tree_refusal(
    subcommand: str, rest: list[str], positionals: list[str], where: tuple[Path, Path]
) -> str | None:
    """Why *subcommand* would act beyond the shell root on the whole repository."""
    root, cwd = where
    if subcommand not in {"merge", "pull", "switch", "reset", "commit", "add", "stash", "checkout"}:
        return None
    if not _extends_above(root, cwd):
        return None
    reason = f"git {subcommand} would act on the whole repository above the shell root"
    if subcommand in _ALWAYS:
        return reason
    if subcommand == "stash":
        return None if positionals and positionals[0] in _STASH_READS else reason
    if subcommand in {"reset", "checkout"}:
        return None if _pathspec_after_dashes(rest) else reason
    if subcommand == "commit":
        return reason if _flag(rest, {"--all"}, "a") else None
    # add: -A/--all/-u/--update without a pathspec stage changes anywhere
    if _flag(rest, {"--all", "--update", "--no-all"}, "Au") and not positionals:
        return reason
    return None


__all__ = ["repository_top", "whole_tree_refusal"]
