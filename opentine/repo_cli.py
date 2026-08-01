"""Facade for the v3 repository CLI: the command registry and the error envelope.

``REPO_COMMANDS`` is the single source of truth for which subcommands the v3 side
owns; ``opentine.cli`` routes through it instead of keeping a second literal list,
and tests/test_repo_cli_routing.py proves every parser choice is routed exactly once.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

import httpx

from opentine._cli_common import _terminal
from opentine._repo_cli_parser import add_repo_parsers
from opentine._repo_cli_plumbing import (
    cmd_clone,
    cmd_context,
    cmd_fetch,
    cmd_fsck,
    cmd_init,
    cmd_migrate_v3,
    cmd_object,
    cmd_pack,
    cmd_push,
    cmd_repo_diff,
    cmd_repo_log,
    cmd_repo_search,
    cmd_repo_show,
)
from opentine._repo_cli_porcelain import cmd_repo_fork, cmd_repo_resume
from opentine._repo_cli_write import cmd_attest, cmd_evaluate, cmd_promote
from opentine._signing_keys import SignatureError

# Re-exported so ``opentine.repo_cli.clone`` stays the live seam that transport tests
# monkeypatch; opentine._repo_cli_plumbing.cmd_clone reads it back off this module.
from opentine.repository.client import clone

RepoHandler = Callable[[argparse.Namespace, object], None]

REPO_COMMANDS: dict[str, RepoHandler] = {
    "attest": cmd_attest,
    "clone": cmd_clone,
    "context": cmd_context,
    "evaluate": cmd_evaluate,
    "fetch": cmd_fetch,
    "fsck": cmd_fsck,
    "init": cmd_init,
    "migrate-v3": cmd_migrate_v3,
    "object": cmd_object,
    "pack": cmd_pack,
    "promote": cmd_promote,
    "push": cmd_push,
    "repo-diff": cmd_repo_diff,
    "repo-fork": cmd_repo_fork,
    "repo-log": cmd_repo_log,
    "repo-resume": cmd_repo_resume,
    "repo-search": cmd_repo_search,
    "repo-show": cmd_repo_show,
}


def cmd_repo(args: argparse.Namespace, console) -> None:
    try:
        REPO_COMMANDS[args.command](args, console)
    # SignatureError is the one opentine error not rooted in ValueError/OSError, and
    # migrate-v3 raises it on its fail-closed path — the expected refusal must read
    # as a refusal, not as an interpreter traceback.
    except (KeyError, OSError, ValueError, SignatureError, httpx.HTTPError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        print(f"tine {_terminal(args.command)}: {_terminal(message)}", file=sys.stderr)
        raise SystemExit(1) from None


__all__ = ["REPO_COMMANDS", "RepoHandler", "add_repo_parsers", "clone", "cmd_repo"]
