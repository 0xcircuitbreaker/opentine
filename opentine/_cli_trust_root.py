"""``tine trust root update``: refresh Sigstore's trusted_root.json over TUF.

The only command that fetches trust material, and only when run. The first
run needs ``--root FILE``: an initial TUF ``root.json`` obtained out of band
(for the Sigstore public-good instance, from the root-signing ceremony
repository github.com/sigstore/root-signing). After a successful update the
installed ``$XDG_CONFIG_HOME/opentine/sigstore/trusted_root.json`` is the
default for ``tine verify --attestation`` keyless checks that name no key file.
"""

from __future__ import annotations

import argparse

from opentine._cli_common import _terminal, console

__all__ = ["add_root_parser", "cmd_trust_root"]


def add_root_parser(group_sub: argparse._SubParsersAction) -> None:
    text = "Sigstore trusted_root.json for keyless verification"
    root = group_sub.add_parser("root", help=text, description=text)
    root.set_defaults(group_handler=cmd_trust_root)
    sub = root.add_subparsers(dest="root_command", metavar="SUBCOMMAND")
    update = sub.add_parser("update", help="Refresh trusted_root.json from a TUF repository")
    update.add_argument("--repo-url", metavar="URL", help="TUF repository (default: Sigstore)")
    update.add_argument("--root", dest="tuf_root", metavar="FILE", help="Initial TUF root.json")
    update.add_argument("--json", action="store_true", help="Emit a JSON object instead")


def cmd_trust_root(args: argparse.Namespace) -> None:
    if getattr(args, "root_command", None) is None:
        from opentine._cli_groups import cmd_group

        return cmd_group(args)
    from opentine._trusted_root import sigstore_dir
    from opentine._tuf_client import TUFError, update
    from opentine._tuf_fetch import FetchError

    try:
        initial = None
        if args.tuf_root:
            with open(args.tuf_root, "rb") as handle:
                initial = handle.read(1 << 20)
        summary = update(sigstore_dir(), repo_url=args.repo_url, initial_root=initial)
    except (OSError, TUFError, FetchError) as exc:
        console.print(f"[red]trust root update failed: {_terminal(exc)}[/]")
        raise SystemExit(1) from None
    if args.json:
        from opentine._cli_json import emit

        emit({"command": "trust root update", **summary})
        return
    console.print(
        f"trusted root installed: {_terminal(summary['trusted_root'])} "
        f"(root v{summary['root']}, targets v{summary['targets']})",
        highlight=False,
    )
