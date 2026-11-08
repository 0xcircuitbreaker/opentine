"""``tine --help`` lists the everyday verbs by section; ``tine help`` reaches the rest.

Advanced verbs are hidden from the listing only: they stay in the subparsers'
``choices``, so they parse, dispatch and print their own ``--help`` unchanged.
"""

from __future__ import annotations

import argparse
import sys

from opentine._cli_groups import add_group_parsers
from opentine._cli_json_fallback import add_json_fallback
from opentine._cli_registry import VISIBLE, advanced
from opentine._cli_schema import COMMANDS as SCHEMA_COMMANDS
from opentine._cli_schema import add_schema_parser
from opentine._user_settings import add_text_flags

_HINT = "Run `tine help --all` for every command, `tine help COMMAND` for one."


def _subparsers(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:
    return next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))


def _rows(names, summaries: dict[str, str]) -> list[str]:
    return [f"    {name:<14}{summaries.get(name, '')}".rstrip() for name in names]


def _everyday(summaries: dict[str, str]) -> list[str]:
    lines: list[str] = []
    for section, summary, verbs in VISIBLE:
        lines += [f"  {section} — {summary}:", *_rows(verbs, summaries)]
    return lines


def finish_parser(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Add ``help`` and hide advanced verbs from ``tine --help``."""
    sub = _subparsers(parser)
    add_schema_parser(sub)  # 0.45: the published JSON Schemas
    helper = sub.add_parser("help", help="Show help for tine or one command")
    helper.add_argument("topic", nargs="?", metavar="COMMAND")
    helper.add_argument("--all", action="store_true", help="List every command by section")
    helper.add_argument(
        "--json", action="store_true", help="Print the command and flag tree as tine-help/1"
    )
    summaries = {action.dest: action.help or "" for action in sub._choices_actions}
    add_group_parsers(sub, summaries)
    summaries = {action.dest: action.help or "" for action in sub._choices_actions}
    parser.tine_summaries = summaries  # type: ignore[attr-defined]
    # Only the help listing reads _choices_actions; parsing reads sub.choices.
    sub._choices_actions = []
    sub.metavar = "COMMAND"
    sub.help = _HINT
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser.epilog = "\n".join(["everyday commands:", *_everyday(summaries)])
    add_json_fallback(parser)  # `--json` on every leaf (0.36, A3)
    add_text_flags(parser)  # `--text` beside every `--json` (0.17 output.format)
    return parser


def cmd_help(args: argparse.Namespace) -> None:
    from opentine._cli_parser import _build_parser

    parser = _build_parser()
    sub = _subparsers(parser)
    summaries = parser.tine_summaries  # type: ignore[attr-defined]
    if getattr(args, "json", False):
        from opentine._cli_help_json import help_tree
        from opentine._cli_json import emit

        tree = help_tree(parser)
        if args.topic:
            tree["commands"] = [c for c in tree["commands"] if c["name"] == args.topic]
            if not tree["commands"]:
                print(f"tine help: no such command {args.topic!r}", file=sys.stderr)
                raise SystemExit(2)
        emit(tree)
    elif args.topic:
        target = sub.choices.get(args.topic)
        if target is None:
            print(f"tine help: no such command {args.topic!r}", file=sys.stderr)
            raise SystemExit(2)
        target.print_help()
    elif args.all:
        lines = ["Everyday:", *_everyday(summaries), "", "Advanced:"]
        print("\n".join(lines + _rows(advanced(sub.choices), summaries)))
    else:
        parser.print_help()


COMMANDS = {"help": cmd_help, **SCHEMA_COMMANDS}

__all__ = ["COMMANDS", "cmd_help", "finish_parser"]
