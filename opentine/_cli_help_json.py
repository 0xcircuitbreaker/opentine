"""``tine help --json``: the command and flag tree as ``tine-help/1`` (0.45).

The web generates its CLI reference from this instead of scraping ``--help``.
It walks the same parser ``tine`` dispatches with, so a verb, a flag or a
choice cannot be documented that does not parse. Commands are sorted by name
and flags kept in declaration order, so the output is stable to diff.
A default that is an absolute path or an environment variable's value is
published as ``null``: it is machine-specific and may be a secret. Group
spellings (``tine share push``) are listed under their group with the verb
they stand for in ``summary``; the registry is :mod:`opentine._cli_registry`.
"""

from __future__ import annotations

import argparse
import os
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from opentine._cli_registry import VISIBLE_COMMANDS
from opentine._version import __version__

SCHEMA = "tine-help/1"
_SKIP = (argparse._HelpAction, argparse._SubParsersAction)


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, list | tuple):
        return [v if v is None or isinstance(v, bool | int | float | str) else str(v)
                for v in value]  # fmt: skip
    return str(value)


def _portable_default(value: Any) -> Any:
    """*value*, unless it is machine-specific: an absolute path (the install
    directory, ``$HOME``) or an environment variable's value, which may be a
    secret. The tree is published, so neither may leak into it."""
    if not isinstance(value, str) or not value:
        return value
    if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
        return None
    if len(value) >= 8 and value in os.environ.values():
        return None
    return value


def _flag(action: argparse.Action) -> dict[str, Any]:
    default = action.default
    if default is argparse.SUPPRESS:
        default = None
    help_text = None if action.help is argparse.SUPPRESS else action.help
    return {
        "flags": list(action.option_strings) or [action.dest],
        "dest": action.dest,
        "help": help_text,
        "metavar": _plain(action.metavar),
        "nargs": _plain(action.nargs),
        "choices": None if action.choices is None else [_plain(c) for c in action.choices],
        "required": bool(action.required)
        if action.option_strings
        else action.nargs not in ("?", "*", argparse.REMAINDER),
        "takes_value": action.nargs != 0,
        "default": _portable_default(_plain(default)),
    }


def _sub(parser: argparse.ArgumentParser) -> argparse._SubParsersAction | None:
    return next((a for a in parser._actions if isinstance(a, argparse._SubParsersAction)), None)


def _node(name: str, parser: argparse.ArgumentParser, summary: str, top: bool) -> dict:
    sub = _sub(parser)
    children = []
    if sub is not None:
        helps = {a.dest: a.help or "" for a in sub._choices_actions}
        for child, p in sorted(sub.choices.items()):
            children.append(_node(child, p, helps.get(child, p.description or ""), False))
    node: dict[str, Any] = {
        "name": name,
        "summary": summary or "",
        "usage": " ".join(parser.format_usage().split()).removeprefix("usage: "),
        "flags": [_flag(a) for a in parser._actions if not isinstance(a, _SKIP)],
        "subcommands": children,
    }
    if top:
        node["advanced"] = name not in VISIBLE_COMMANDS
    return node


def help_tree(parser: argparse.ArgumentParser) -> dict[str, Any]:
    """The ``tine-help/1`` document for the built ``tine`` *parser*."""
    sub = _sub(parser)
    summaries: dict[str, str] = getattr(parser, "tine_summaries", {})
    commands = [] if sub is None else [
        _node(name, child, summaries.get(name, ""), True)
        for name, child in sorted(sub.choices.items())
    ]  # fmt: skip
    return {
        "command": "help",
        "schema": SCHEMA,
        "version": __version__,
        "prog": "tine",
        "global_flags": [_flag(a) for a in parser._actions if not isinstance(a, _SKIP)],
        "commands": commands,
    }


__all__ = ["SCHEMA", "help_tree"]
