"""``tine plugins list|check|allow`` and ``tine experts PATH`` (0.47).

``plugins list`` shows every installed entry point in the four plugin groups
and whether the loading rules (:mod:`opentine.plugins`) would let it load; it
imports nothing. ``plugins check KIND NAME`` loads one and checks its
interface. ``plugins allow KIND NAME`` pins the installed distribution that
provides it, at its current version, in the user's allow-list. ``--json``
follows ``tine-cli-plugins-1``.

``tine experts PATH`` ranks agents and humans by attributed lines and verified
runs (:mod:`opentine._experts`); ``--json`` follows ``tine-experts-1``.
"""

from __future__ import annotations

import argparse
from typing import Any

from rich.markup import escape

from opentine._cli_common import console
from opentine._cli_errors import NOT_FOUND, USAGE, fail

KINDS = ("importer", "signer", "scorer", "snapshot")


def add_extend_parsers(sub: Any) -> None:
    plugins = sub.add_parser("plugins", help="List, check and allow entry-point plugins")
    actions = plugins.add_subparsers(dest="plugins_action", required=True)
    listing = actions.add_parser("list", help="Installed plugins and whether they may load")
    listing.add_argument("--kind", choices=KINDS)
    listing.add_argument("--json", action="store_true")
    for verb, text in (("check", "Load one plugin and check its interface"),
                       ("allow", "Pin an installed plugin in your allow-list")):  # fmt: skip
        action = actions.add_parser(verb, help=text)
        action.add_argument("kind", choices=KINDS)
        action.add_argument("name")
        action.add_argument("--json", action="store_true")
    experts = sub.add_parser("experts", help="Rank agents and humans who wrote PATH")
    experts.add_argument("path", metavar="PATH", help="File or directory in a git work tree")
    experts.add_argument("--rev", default="HEAD", help="Revision to blame (default HEAD)")
    experts.add_argument("--pubkey", metavar="KEY", help="Ed25519 key the notes must verify by")
    experts.add_argument("--limit", type=int, default=0, help="Show at most N experts")
    experts.add_argument("--json", action="store_true")


def _emit(args: argparse.Namespace, payload: dict[str, Any]) -> None:
    from opentine._cli_json import emit

    if args.json:
        emit({"command": "plugins", "action": args.plugins_action, **payload})
        return
    for row in payload.get("plugins", []):
        mark = "[green]allowed[/]" if row["allowed"] else "[yellow]blocked[/]"
        console.print(
            f"{mark}  {row['kind']:<8} {escape(row['name'])}  "
            f"{escape(row['distribution'])} {escape(row['version'])}  {escape(row['reason'])}"
        )
    if not payload.get("plugins"):
        console.print("no plugins installed")


def cmd_plugins(args: argparse.Namespace) -> None:
    from opentine import plugins
    from opentine._plugins_allow import AllowListError, add

    try:
        if args.plugins_action == "list":
            found = plugins.discover((args.kind,) if args.kind else plugins.KINDS)
            _emit(args, {"ok": True, "plugins": [c.to_dict() for c in found]})
            return
        candidates = [c for c in plugins.discover((args.kind,)) if c.name == args.name]
        if not candidates:
            fail(f"no {args.kind} plugin named {args.name!r} is installed", NOT_FOUND)
        if args.plugins_action == "allow":
            found = candidates[0]
            add(found.kind, found.name, found.distribution, found.version)
            candidates = [c for c in plugins.discover((args.kind,)) if c.name == args.name]
        else:
            plugins.load(args.kind, args.name)
    except (AllowListError, plugins.PluginError) as exc:
        fail(str(exc), USAGE if isinstance(exc, AllowListError) else 1, cause=exc)
    _emit(args, {"ok": True, "plugins": [c.to_dict() for c in candidates]})


def cmd_experts(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine._experts import experts
    from opentine._git_link import GitLinkError

    key = None
    if args.pubkey:
        from opentine._signing_keys import ed25519_public_from_file

        key = ed25519_public_from_file(args.pubkey)
    try:
        record = experts(".", args.path, rev=args.rev, public_key=key, limit=args.limit)
    except (GitLinkError, ValueError) as exc:
        fail(str(exc), USAGE, prefix="experts: ", cause=exc)
    if args.json:
        emit(record)
        return
    console.print(f"{escape(record['path'])} at {record['revision'][:12]}: "
                  f"{record['total_lines']} lines in {record['files']} file(s)")  # fmt: skip
    for row in record["experts"]:
        console.print(
            f"{row['rank']:>3}. {row['kind']:<5} {escape(row['id'])}  {row['lines']} lines "
            f"({row['share']:.1%}), {row['runs']} runs, {row['verified_runs']} verified"
        )


COMMANDS = {"plugins": cmd_plugins, "experts": cmd_experts}

__all__ = ["COMMANDS", "add_extend_parsers", "cmd_experts", "cmd_plugins"]
