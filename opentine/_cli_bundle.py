"""``tine bundle``: share runs as one offline file or over a plain git remote."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from opentine import _bundle, _bundle_git
from opentine.repo import Repo
from opentine.repository.store import _atomic_bytes


def _print(payload: dict) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def cmd_bundle(args: argparse.Namespace, console) -> None:
    action = args.bundle_action
    if action == "verify":
        checked = _bundle.verify(_bundle.read_file(args.file))
        _print(
            {
                "bundle": checked.digest,
                "objects": checked.objects,
                "pack": checked.pack_id,
                "refs": checked.refs,
                "verified": True,
            }
        )
        return
    repo = Repo.open(args.repo)
    if action == "create":
        if bool(args.refs) == bool(args.all):
            raise ValueError("name refs to bundle, or pass --all (not both)")
        data = _bundle.create(repo, args.refs or None)
        _atomic_bytes(Path(args.file), data)
        checked = _bundle.verify(data)
        _print({"bundle": checked.digest, "bytes": len(data), "refs": checked.refs})
    elif action in ("unbundle", "import"):
        name = args.as_name or _bundle.namespace(Path(args.file).name)
        _print(_bundle.unbundle(repo, _bundle.read_file(args.file), name, force=args.force))
    elif action == "push":
        if bool(args.refs) and args.all:
            raise ValueError("name refs to push, or pass --all (not both)")
        _print(_bundle_git.push(repo, args.remote, args.refs or None, timeout=args.timeout))
    elif action == "fetch":
        name = args.as_name or _bundle.namespace(args.remote)
        _print(_bundle_git.fetch(repo, args.remote, name, force=args.force, timeout=args.timeout))
    else:
        raise ValueError("choose an action: create, verify, unbundle, push or fetch")


def add_bundle_parsers(sub: argparse._SubParsersAction) -> None:
    bundle = sub.add_parser(
        "bundle", help="Share runs as one verifiable file or over a plain git remote"
    )
    actions = bundle.add_subparsers(dest="bundle_action")
    create = actions.add_parser("create", help="Write refs and their objects to one file")
    create.add_argument("file")
    create.add_argument("refs", nargs="*", help="Refs to bundle (heads/NAME, tags/NAME, ...)")
    create.add_argument("--all", action="store_true", help="Every local ref except remotes/*")
    verify = actions.add_parser("verify", help="Check a bundle's integrity without importing")
    verify.add_argument("file")
    for verb in ("unbundle", "import"):
        imp = actions.add_parser(verb, help="Verify, then import into remotes/<name>/*")
        imp.add_argument("file")
        _import_args(imp)
    push = actions.add_parser("push", help="Store a bundle at refs/tine/bundle on a git remote")
    push.add_argument("remote", help="A git URL (https, ssh, file) or a local repository path")
    push.add_argument("refs", nargs="*", help="Refs to push (default: every local ref)")
    push.add_argument("--all", action="store_true", help="Every local ref (the default)")
    push.add_argument("--timeout", type=float, default=120.0)
    fetch = actions.add_parser("fetch", help="Fetch and import refs/tine/bundle from a git remote")
    fetch.add_argument("remote", help="A git URL (https, ssh, file) or a local repository path")
    fetch.add_argument("--timeout", type=float, default=120.0)
    _import_args(fetch)
    for parser in (create, verify, push):
        parser.add_argument("--repo", default=".")


def _import_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--as", dest="as_name", metavar="NAME", help="Namespace under remotes/")
    parser.add_argument("--force", action="store_true", help="Allow non-fast-forward updates")
    parser.add_argument("--repo", default=".")


COMMANDS = {"bundle": cmd_bundle}

__all__ = ["COMMANDS", "add_bundle_parsers", "cmd_bundle"]
