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
    ("Repository", "set up and organise a repository", ("init", "branch", "tag")),
    ("Help", "find every other command", ("help",)),
)

VISIBLE_COMMANDS: frozenset[str] = frozenset(v for _, _, verbs in VISIBLE for v in verbs)

# Old spelling -> new argv prefix. Empty until a later phase renames something.
ALIASES: dict[str, tuple[str, ...]] = {}


def advanced(all_commands) -> list[str]:
    """Every parseable verb ``tine --help`` does not list, sorted."""
    return sorted(set(all_commands) - VISIBLE_COMMANDS)


__all__ = ["ALIASES", "VISIBLE", "VISIBLE_COMMANDS", "advanced"]
