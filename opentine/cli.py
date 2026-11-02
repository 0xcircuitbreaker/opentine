"""OpenTine command-line facade composed from small command modules."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable

import opentine._cli_common as _common
from opentine._cli_bisect import COMMANDS as BISECT_COMMANDS
from opentine._cli_common import (
    BRAND,
    BRAND_DIM,
    HARNESS_FACTORIES,
    RUNS_DIR,
    STEP_ICONS,
    _cost_str,
    _display_value,
    _find_run,
    _harness_from_args,
    _index_update,
    _resolve_step_ref,
    _run_context,
    _runs_dir,
    _step_label,
    console,
)
from opentine._cli_evidence import COMMANDS as EVIDENCE_COMMANDS
from opentine._cli_execute import cmd_cost, cmd_price, cmd_run, cmd_run_harness, cmd_show
from opentine._cli_export import cmd_export
from opentine._cli_fanout import split_command
from opentine._cli_fleet import COMMANDS as FLEET_COMMANDS
from opentine._cli_flow import cmd_diff, cmd_fork, cmd_resume
from opentine._cli_fold import rewrite as fold_rewrite
from opentine._cli_git_refs import cmd_tag_v3
from opentine._cli_gitlink import COMMANDS as GITLINK_COMMANDS
from opentine._cli_groups import COMMANDS as GROUP_COMMANDS
from opentine._cli_groups import notice as group_notice
from opentine._cli_groups import rewrite as group_rewrite
from opentine._cli_guard import guarded_dispatch
from opentine._cli_harnesses import cmd_harnesses
from opentine._cli_help import COMMANDS as HELP_COMMANDS
from opentine._cli_hook import COMMANDS as HOOK_COMMANDS
from opentine._cli_import import cmd_import
from opentine._cli_listing import cmd_ls, cmd_reindex, cmd_search, cmd_tag
from opentine._cli_media import COMMANDS as MEDIA_COMMANDS
from opentine._cli_migrate import cmd_migrate
from opentine._cli_parser import _add_filter_args, _add_harness_args, _build_parser
from opentine._cli_plugin import COMMANDS as PLUGIN_COMMANDS
from opentine._cli_record import COMMANDS as RECORD_COMMANDS
from opentine._cli_render import (
    STATUS_COLORS,
    _budget_str,
    _entries_table,
    _has_filters,
    _print_diff_table,
    _print_run_tree,
    _query_from_ls_args,
)
from opentine._cli_replay import cmd_replay
from opentine._cli_rewind import COMMANDS as REWIND_COMMANDS
from opentine._cli_run_model import cmd_run_model
from opentine._cli_security import (
    _verify_signature_if_requested,
    cmd_keygen,
    cmd_sign,
    cmd_verify,
)
from opentine._cli_stats import cmd_stats
from opentine._cli_storage import STORAGE_COMMANDS
from opentine._cli_unify import expand_alias, tag_is_v3, v3_argv
from opentine._cli_view import COMMANDS as VIEW_COMMANDS
from opentine._cli_who import COMMANDS as ACTION_COMMANDS
from opentine._user_settings import apply_output_format, cmd_user_config, is_user_config
from opentine.pricing_cli import cmd_pricing
from opentine.remote.server import cmd_serve
from opentine.repo_cli import REPO_COMMANDS, cmd_repo

# The legacy (v2) command table. REPO_COMMANDS owns the v3 side; the two must stay
# disjoint and together cover every parser choice — tests/test_repo_cli_routing.py.
LEGACY_COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {
    "cost": cmd_cost,
    "diff": cmd_diff,
    "export": cmd_export,
    "fork": cmd_fork,
    "harnesses": cmd_harnesses,
    **STORAGE_COMMANDS,
    "import": cmd_import,
    "keygen": cmd_keygen,
    "ls": cmd_ls,
    "migrate": cmd_migrate,
    "price": cmd_price,
    "pricing": lambda namespace: cmd_pricing(namespace, console),
    "reindex": cmd_reindex,
    "replay": cmd_replay,
    "resume": cmd_resume,
    "run": cmd_run,
    "search": cmd_search,
    "serve": lambda namespace: cmd_serve(namespace, console),
    "show": cmd_show,
    "sign": cmd_sign,
    "stats": cmd_stats,
    "tag": cmd_tag,
    "verify": cmd_verify,
    **ACTION_COMMANDS,
    **GITLINK_COMMANDS,
    **BISECT_COMMANDS,
    **MEDIA_COMMANDS,
    **RECORD_COMMANDS,
    **REWIND_COMMANDS,
    **VIEW_COMMANDS,
    **EVIDENCE_COMMANDS,
    **HOOK_COMMANDS,
    **PLUGIN_COMMANDS,
    **FLEET_COMMANDS,
    **HELP_COMMANDS,
    **GROUP_COMMANDS,
}


def main(argv: list[str] | None = None) -> None:
    """Run one ``tine`` invocation; *argv* defaults to the process arguments."""
    _common.RUNS_DIR = RUNS_DIR
    parser, args = parse(list(sys.argv[1:] if argv is None else argv))
    if args.no_compress:
        os.environ["OPENTINE_COMPRESS"] = "0"
    guarded_dispatch(lambda: _dispatch(parser, args))


def parse(argv: list[str], parser=None) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    """Alias expansion and the parse ``main`` does, without running anything."""
    parser = parser or _build_parser()
    argv = expand_alias(parser, list(argv))
    group_notice(argv)
    head, tail = split_command(
        group_rewrite(argv)
    )  # `tine repo storage gc` -> `tine gc`  # `tine fan-out ... -- CMD`: CMD is never parsed
    args = parser.parse_args(fold_rewrite(parser, head))  # `tine log --search Q` -> `tine search Q`
    apply_output_format(args, head)  # output.format / OPENTINE_OUTPUT default --json
    args.member_command = tail
    args.tine_argv = argv  # `tine run --parallel` re-runs this invocation per member
    return parser, args


def resolve(parser, args) -> tuple[Callable | None, argparse.Namespace, bool]:
    """``(handler, args, via_repo)`` the dispatcher would call; the handler is not run.

    *via_repo* handlers take ``(args, console)`` through ``cmd_repo``. A None handler
    means a bare ``tine`` (or, for a non-None command, an unrouted choice).
    """
    # Plain verbs act on the v3 repository when their arguments name things in it.
    if args.command == "tag" and tag_is_v3(args):
        args.name = args.run_id
        args.repo = args.repo or "."
        return cmd_tag_v3, args, True
    if args.command in {"show", "diff", "search", "fork"} and (argv := v3_argv(args)):
        args = parser.parse_args(argv)
    if args.command == "tag" and args.run_id is None:
        parser.error("tag: name a legacy run (with --add/--remove/--list) or run inside a v3 repo")
    if is_user_config(args):  # `tine config set output.format json`: no repository
        return cmd_user_config, args, False
    if args.command == "config" and args.setting_value is not None:
        parser.error(f"unrecognized arguments: {args.setting_value}")
    if owned := getattr(args, "group_handler", None):  # `tine trust policy ...`
        return owned, args, False
    if args.command in LEGACY_COMMANDS:
        return LEGACY_COMMANDS[args.command], args, False
    if args.command in REPO_COMMANDS:
        return REPO_COMMANDS[args.command], args, True
    return None, args, False


def _dispatch(parser, args) -> None:
    handler, args, via_repo = resolve(parser, args)
    if handler is not None and via_repo:
        cmd_repo(args, console, handler)
    elif handler is not None:
        handler(args)
    elif args.command is None:
        console.print(f"\n  [{BRAND}]opentine[/] — git for agent runs\n")
        parser.print_help()
    else:
        # A parser choice nobody routes is a packaging bug, not a usage banner: the
        # old fall-through printed help and exited 0, so CI never saw the hole.
        print(f"tine: unrouted command {args.command!r}", file=sys.stderr)
        raise SystemExit(1)


__all__ = [
    "BRAND",
    "BRAND_DIM",
    "HARNESS_FACTORIES",
    "LEGACY_COMMANDS",
    "REPO_COMMANDS",
    "RUNS_DIR",
    "STATUS_COLORS",
    "STEP_ICONS",
    "_add_filter_args",
    "_add_harness_args",
    "_budget_str",
    "_build_parser",
    "_cost_str",
    "_display_value",
    "_entries_table",
    "_find_run",
    "_harness_from_args",
    "_has_filters",
    "_index_update",
    "_print_diff_table",
    "_print_run_tree",
    "_query_from_ls_args",
    "_resolve_step_ref",
    "_run_context",
    "_runs_dir",
    "_step_label",
    "_verify_signature_if_requested",
    "cmd_cost",
    "cmd_diff",
    "cmd_export",
    "cmd_fork",
    "cmd_import",
    "cmd_keygen",
    "cmd_ls",
    "cmd_migrate",
    "cmd_price",
    "cmd_reindex",
    "cmd_replay",
    "cmd_resume",
    "cmd_run",
    "cmd_run_harness",
    "cmd_run_model",
    "cmd_search",
    "cmd_show",
    "cmd_sign",
    "cmd_stats",
    "cmd_tag",
    "cmd_verify",
    "console",
    "main",
    "parse",
    "resolve",
]


if __name__ == "__main__":
    main()
