"""Parsers and the command table for the git-style porcelain verbs (0.12).

``remote``, ``pull``, ``branch``, ``verify-tag``, ``reflog``, ``reset``,
``config``, ``log``, ``rebase`` and ``cherry-pick`` act on a v3 repository and
route through ``repo_cli.REPO_COMMANDS``. ``tag`` (v3 form) shares the legacy
``tag`` parser and is routed by ``_cli_unify``.
"""

from __future__ import annotations

import argparse

from opentine._cli_bundle import COMMANDS as BUNDLE_COMMANDS
from opentine._cli_bundle import add_bundle_parsers
from opentine._cli_git_log import cmd_log
from opentine._cli_git_refs import (
    cmd_branch,
    cmd_config,
    cmd_reflog,
    cmd_remote,
    cmd_reset,
    cmd_verify_tag,
)
from opentine._cli_git_rewrite import cmd_cherry_pick, cmd_rebase
from opentine._cli_git_sync import cmd_pull
from opentine._repo_cli_keys import add_key_args

COMMANDS = {
    "branch": cmd_branch,
    "cherry-pick": cmd_cherry_pick,
    "config": cmd_config,
    "log": cmd_log,
    "pull": cmd_pull,
    "rebase": cmd_rebase,
    "reflog": cmd_reflog,
    "remote": cmd_remote,
    "reset": cmd_reset,
    "verify-tag": cmd_verify_tag,
    **BUNDLE_COMMANDS,
}


def _common(parser: argparse.ArgumentParser, *, json: bool = True) -> None:
    parser.add_argument("--repo", default=".")
    if json:
        parser.add_argument("--json", action="store_true", help="Emit a JSON object instead")


def add_git_parsers(sub: argparse._SubParsersAction) -> None:
    add_bundle_parsers(sub)
    remote = sub.add_parser("remote", help="Manage named remotes (stored in .tine/porcelain.json)")
    actions = remote.add_subparsers(dest="remote_action")
    add = actions.add_parser("add", help="Add a remote")
    add.add_argument("name")
    add.add_argument("url")
    add.add_argument("--tenant")
    add.add_argument("--token-file", metavar="PATH", help="Read the bearer token from PATH")
    for verb in ("rm", "remove"):
        actions.add_parser(verb, help="Remove a remote").add_argument("name")
    rename = actions.add_parser("rename", help="Rename a remote")
    rename.add_argument("name")
    rename.add_argument("new_name")
    actions.add_parser("ls", help="List remotes")
    _common(remote)

    pull = sub.add_parser("pull", help="Fetch, then fast-forward the local ref (never merges)")
    pull.add_argument("remote", nargs="?", help="A remote name or URL (default: origin)")
    pull.add_argument("--ref", default="heads/main")
    pull.add_argument("--tenant")
    pull.add_argument("--token")
    pull.add_argument("--token-file", metavar="PATH")
    pull.add_argument("--allow-insecure", action="store_true")
    pull.add_argument("--depth", type=int)
    _common(pull)

    branch = sub.add_parser("branch", help="List, create or delete heads/* branches")
    branch.add_argument("name", nargs="?")
    branch.add_argument("start", nargs="?", help="Run or ref to point at (default heads/main)")
    branch.add_argument("-d", "--delete", metavar="NAME")
    branch.add_argument("-a", "--all", action="store_true", help="Include experiments/remotes")
    branch.add_argument("-f", "--force", action="store_true")
    _common(branch)

    verify_tag = sub.add_parser("verify-tag", help="Verify a signed tag (tine tag -s)")
    verify_tag.add_argument("name")
    add_key_args(verify_tag, signing=False)
    _common(verify_tag)

    reflog = sub.add_parser("reflog", help="Show where a ref has pointed")
    reflog.add_argument("ref", nargs="?", default="heads/main")
    reflog.add_argument("--limit", type=int, default=50)
    _common(reflog)

    reset = sub.add_parser("reset", help="Point a ref at a run (compare-and-swap)")
    reset.add_argument("ref")
    reset.add_argument("target", help="A run oid or a ref")
    reset.add_argument("--expect", metavar="OID", help="Refuse unless the ref holds this oid")
    _common(reset, json=False)

    config = sub.add_parser("config", help="Get or set porcelain settings and aliases")
    config.add_argument("key", nargs="?")
    config.add_argument("value", nargs="?")
    config.add_argument("--list", "-l", action="store_true")
    config.add_argument("--unset", action="store_true")
    config.add_argument("--trust", action="store_true", help="Trust this repo's porcelain file")
    _common(config)

    log = sub.add_parser("log", help="Run history; --graph draws forks across refs")
    log.add_argument("ref", nargs="?")
    log.add_argument("--graph", action="store_true")
    log.add_argument("--all", action="store_true", help="Every run ref, not just one")
    log.add_argument("--oneline", action="store_true")
    log.add_argument("--limit", type=int, default=None)
    log.add_argument("--commit", metavar="SHA", help="Runs behind a git commit (tine git log)")
    log.add_argument("--pr", type=int, metavar="N", help="Runs behind a GitHub PR (tine git log)")
    _common(log)

    rebase = sub.add_parser("rebase", help="Fork a run onto a different model")
    rebase.add_argument("run")
    rebase.add_argument("--onto-model", required=True, metavar="MODEL")
    rebase.add_argument("--from-step", default="1", help="Keep steps 1..N (default 1)")
    rebase.add_argument("--prompt", help="Also override the prompt")
    rebase.add_argument("--ref", help="Default experiments/rebase/<id>")
    rebase.add_argument("--force", action="store_true", help="Move an existing --ref")
    _common(rebase)

    pick = sub.add_parser("cherry-pick", help="Copy one step onto the end of another run")
    pick.add_argument("pick", metavar="RUN:STEP")
    pick.add_argument("--onto", required=True, metavar="RUN")
    pick.add_argument("--ref", help="Default experiments/cherry-pick/<id>")
    pick.add_argument("--force", action="store_true", help="Move an existing --ref")
    _common(pick)


__all__ = ["COMMANDS", "add_git_parsers"]
