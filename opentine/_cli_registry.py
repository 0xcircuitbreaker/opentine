"""Which ``tine`` verbs ``tine --help`` shows, grouped; everything else is advanced.

0.16 "Simplify" narrows the everyday surface to a dozen verbs without moving or
renaming any command: every verb stays parseable and reaches the same handler
(pinned by tests/cli_compat_table.py). Groups whose umbrella verb does not exist
yet (``trust``, ``share``, ``repo``) list the verbs that exist today in that
section; later phases swap them for the umbrella and record the old spelling in
``ALIASES``.
"""

from __future__ import annotations

# (section, one-line summary, verbs) in display order.
VISIBLE: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("Record", "capture agent runs", ("run", "import")),
    ("Inspect", "read history and runs", ("log", "show")),
    ("Branch", "explore from any step", ("fork", "replay")),
    ("Trust", "verify and sign what was recorded", ("verify", "sign", "attest")),
    ("Collaborate", "share runs with others", ("push", "fetch", "pull", "clone", "bundle")),
    ("Agents", "agent identities and keys", ("agent",)),
    ("Repository", "set up and organise a repository", ("init", "repo", "branch", "tag")),
    ("Help", "find every other command", ("help",)),
)

VISIBLE_COMMANDS: frozenset[str] = frozenset(v for _, _, verbs in VISIBLE for v in verbs)

# Old spelling -> new argv prefix. Empty until a later phase renames something.
ALIASES: dict[str, tuple[str, ...]] = {}


# Noun groups: ``tine GROUP WORDS... REST`` is re-parsed as ``tine VERB... REST`` (see
# opentine/_cli_groups.py), so both spellings reach one handler with one Namespace.
# Keys are the words after GROUP; values are the argv prefix they stand for.
GROUPS: dict[str, tuple[str, dict[tuple[str, ...], tuple[str, ...]]]] = {
    "repo": (
        "Set up, maintain and integrate a v3 repository",
        {
            **{(v,): (v,) for v in ("init", "config", "worktree", "branch", "reset")},
            **{(v,): (v,) for v in ("reflog", "archive", "pack", "migrate", "serve")},
            **{("storage", v): (v,) for v in ("du", "gc", "repack", "prune", "compress")},
            ("storage", "fsck"): ("fsck",),
            ("storage", "reindex"): ("reindex",),
            **{("integrate", v): (v,) for v in ("hook", "plugin", "harnesses", "git")},
        },
    ),
}

# A flag that swaps the target verb: ``tine repo migrate --to-v3 X`` -> ``migrate-v3 X``.
SWITCHES: dict[tuple[str, ...], dict[str, tuple[str, ...]]] = {
    ("repo", "migrate"): {"--to-v3": ("migrate-v3",)},
}

# Summaries for the intermediate group words in ``tine repo --help``.
NODES: dict[tuple[str, ...], str] = {
    ("repo", "storage"): "Disk usage, gc, repack, prune, compress, fsck, reindex",
    ("repo", "integrate"): "Agent-CLI hooks, plugins, harnesses and git links",
}

# Old top-level verb -> its new spelling. A verb listed here prints a one-line
# stderr notice when spelled the old way (OPENTINE_NO_DEPRECATION=1 silences it).
# Empty in 0.16: old spellings keep working silently.
DEPRECATED: dict[str, str] = {}


def advanced(all_commands) -> list[str]:
    """Every parseable verb ``tine --help`` does not list, sorted."""
    return sorted(set(all_commands) - VISIBLE_COMMANDS)


__all__ = [
    "ALIASES",
    "DEPRECATED",
    "GROUPS",
    "NODES",
    "SWITCHES",
    "VISIBLE",
    "VISIBLE_COMMANDS",
    "advanced",
]
