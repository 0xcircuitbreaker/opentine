"""OpenTine command-line facade composed from small command modules."""

from __future__ import annotations

import opentine._cli_common as _common
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
from opentine._cli_execute import cmd_cost, cmd_run, cmd_run_harness, cmd_show
from opentine._cli_flow import cmd_diff, cmd_fork, cmd_replay, cmd_resume
from opentine._cli_listing import cmd_ls, cmd_reindex, cmd_search, cmd_tag
from opentine._cli_migrate import cmd_migrate
from opentine._cli_parser import _add_filter_args, _add_harness_args, _build_parser
from opentine._cli_render import (
    STATUS_COLORS,
    _budget_str,
    _entries_table,
    _has_filters,
    _print_diff_table,
    _print_run_tree,
    _query_from_ls_args,
)
from opentine._cli_security import (
    _verify_signature_if_requested,
    cmd_keygen,
    cmd_sign,
    cmd_verify,
)
from opentine.pricing_cli import cmd_pricing


def main() -> None:
    _common.RUNS_DIR = RUNS_DIR
    parser = _build_parser()
    args = parser.parse_args()
    commands = {
        "cost": cmd_cost,
        "diff": cmd_diff,
        "fork": cmd_fork,
        "keygen": cmd_keygen,
        "ls": cmd_ls,
        "migrate": cmd_migrate,
        "pricing": lambda namespace: cmd_pricing(namespace, console),
        "reindex": cmd_reindex,
        "replay": cmd_replay,
        "resume": cmd_resume,
        "run": cmd_run,
        "search": cmd_search,
        "show": cmd_show,
        "sign": cmd_sign,
        "tag": cmd_tag,
        "verify": cmd_verify,
    }
    if args.command in commands:
        commands[args.command](args)
    else:
        console.print(f"\n  [{BRAND}]opentine[/] — git for agent runs\n")
        parser.print_help()


__all__ = [
    "BRAND",
    "BRAND_DIM",
    "HARNESS_FACTORIES",
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
    "cmd_fork",
    "cmd_keygen",
    "cmd_ls",
    "cmd_migrate",
    "cmd_reindex",
    "cmd_replay",
    "cmd_resume",
    "cmd_run",
    "cmd_run_harness",
    "cmd_search",
    "cmd_show",
    "cmd_sign",
    "cmd_tag",
    "cmd_verify",
    "console",
    "main",
]


if __name__ == "__main__":
    main()
