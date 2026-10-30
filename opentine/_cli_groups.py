"""Noun groups: ``tine repo storage gc ...`` is ``tine gc ...`` by argv rewrite.

The groups and their word -> verb maps live in ``_cli_registry.GROUPS``. Routing
generalises the plain-verb -> ``repo-*`` rewrite in ``_cli_unify``: the group words
are replaced by the old verb's argv prefix *before* parsing, so the new spelling
is parsed by the very parser of the old one and reaches the same handler with the
same Namespace. Everything after the matched words (flags, positionals, a ``--``
passthrough tail) is kept verbatim; ``cli.parse`` still records the argv the user
typed as ``args.tine_argv``.

The group itself is a real subparser (with one child per word) only so that
``tine repo``, ``tine repo --help`` and ``tine help repo`` list the subcommands;
a bare or unknown group word falls through to it and prints that listing.
"""

from __future__ import annotations

import argparse
import os
import sys

from opentine._cli_registry import DEPRECATED, EXTENDED, GROUPS, NODES, SWITCHES


def rewrite(argv: list[str]) -> list[str]:
    """The old-verb argv a group spelling stands for; any other argv is unchanged."""
    if bundle := _bundle_target(argv):
        return ["bundle", "verify", bundle]
    if not argv or argv[0] not in GROUPS:
        return argv
    group, words = argv[0], GROUPS[argv[0]][1]
    for size in sorted({len(key) for key in words}, reverse=True):
        key = tuple(argv[1 : 1 + size])
        if key in words:
            rest = argv[1 + size :]
            return [*_switch((group, *key), rest, words[key]), *_drop((group, *key), rest)]
    return argv


def _bundle_target(argv: list[str]) -> str | None:
    """``tine verify FILE`` on a ``tine bundle`` file is ``tine bundle verify FILE``.

    Only the bare two-word form is routed: run-verify flags mean a run.
    """
    if len(argv) != 2 or argv[0] != "verify" or argv[1].startswith("-"):
        return None
    from opentine._bundle import MAGIC

    try:
        with open(argv[1], "rb") as handle:
            return argv[1] if handle.read(len(MAGIC)) == MAGIC else None
    except OSError:
        return None


def _head(rest: list[str]) -> list[str]:
    return rest[: rest.index("--")] if "--" in rest else rest


def _switch(path: tuple[str, ...], rest: list[str], prefix: tuple[str, ...]) -> tuple[str, ...]:
    for flag, target in SWITCHES.get(path, {}).items():
        if flag in _head(rest):
            return target
    return prefix


def _drop(path: tuple[str, ...], rest: list[str]) -> list[str]:
    flags = SWITCHES.get(path, {})
    head = _head(rest)
    return [a for a in head if a not in flags] + rest[len(head) :]


def notice(argv: list[str]) -> None:
    """The opt-in stderr notice for an old spelling listed in ``DEPRECATED``."""
    if argv and argv[0] in DEPRECATED and not os.environ.get("OPENTINE_NO_DEPRECATION"):
        print(
            f"tine: `tine {argv[0]}` is now `{DEPRECATED[argv[0]]}`; the old spelling still works",
            file=sys.stderr,
        )


def add_group_parsers(sub: argparse._SubParsersAction, summaries: dict[str, str]) -> None:
    """One listing-only subparser per group, children summarised from their verbs."""
    for group, (summary, words) in GROUPS.items():
        nodes: dict[tuple[str, ...], argparse._SubParsersAction] = {}
        if group in EXTENDED:  # list the words under the verb's own subcommands
            parser = sub.choices[group]
            nodes[()] = next(
                a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
            )
        else:
            parser = sub.add_parser(group, help=summary, description=summary)
            nodes[()] = parser.add_subparsers(dest=f"{group}_command", metavar="SUBCOMMAND")
        for key, prefix in words.items():
            for depth in range(1, len(key)):
                if key[:depth] not in nodes:
                    text = NODES.get((group, *key[:depth]), "")
                    child = nodes[key[: depth - 1]].add_parser(
                        key[depth - 1], help=text, description=text
                    )
                    nodes[key[:depth]] = child.add_subparsers(metavar="SUBCOMMAND")
            text = summaries.get(prefix[0], "")
            nodes[key[:-1]].add_parser(key[-1], help=text, add_help=False)


def cmd_group(args: argparse.Namespace) -> None:
    """A bare (or incomplete) group spelling: list what it contains."""
    from opentine._cli_parser import _build_parser

    parser = _build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    target = sub.choices[args.command]
    word = getattr(args, f"{args.command}_command", None)
    if word:
        inner = next(a for a in target._actions if isinstance(a, argparse._SubParsersAction))
        target = inner.choices[word]
    target.print_help()


COMMANDS = {group: cmd_group for group in GROUPS if group not in EXTENDED}

__all__ = ["COMMANDS", "add_group_parsers", "cmd_group", "notice", "rewrite"]
