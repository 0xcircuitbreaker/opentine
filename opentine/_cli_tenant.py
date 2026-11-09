"""``tine tenant export|import``: leave a hosted ``tine serve`` with everything (0.50).

``tenant export [--remote REMOTE] --out DIR`` writes the tenant's refs and
objects as one bundle, its Reviews, its transparency-log entries and its share
metadata to DIR (``opentine._tenant_move``; only formats frozen at 0.48).
``tenant import DIR`` installs that export into a local repository (``--repo``,
the same ref names) or, with ``--remote``, pushes it to another ``tine serve``
tenant. ``tine verify RUN --offline`` then gives the same report on either
side. ``--json`` prints one ``tine-cli-tenant-1`` document.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from opentine._cli_remote_target import add_remote_args, resolve


def add_tenant_parsers(sub: argparse._SubParsersAction) -> None:
    tenant = sub.add_parser("tenant", help="Export a hosted tenant, or import an export")
    actions = tenant.add_subparsers(dest="tenant_action", required=True)
    out = actions.add_parser("export", help="Write a tenant's runs, refs and Reviews to a folder")
    out.add_argument("--out", required=True, metavar="DIR", help="Folder to write (created)")
    into = actions.add_parser("import", help="Install an export locally or on another remote")
    into.add_argument("source", metavar="DIR", help="A `tine tenant export` folder")
    for parser in (out, into):
        add_remote_args(parser)
        parser.add_argument("--repo", default=".", help="Local repository (and its remotes)")
        parser.add_argument("--json", action="store_true")
    out.set_defaults(timeout=120.0)
    into.set_defaults(timeout=120.0)


def _print(args, body: dict) -> None:
    if args.json:
        from opentine._cli_json import emit

        emit({"schema": "tine-cli-tenant/1", **body})
        return
    for name, oid in sorted(body["refs"].items()):
        print(f"{name}\t{oid}")
    print(f"{len(body['refs'])} refs, {len(body['reviews'])} reviews", end="")
    if body["command"] == "tenant-export":
        print(f", {body['log_entries']} log entries -> {body['out']}")
    else:
        print(f" -> {body['into']}")


def cmd_tenant(args: argparse.Namespace) -> None:
    from opentine import _tenant_move
    from opentine._cli_errors import fail

    try:
        if args.tenant_action == "export":
            base, tenant, token = resolve(args, args.remote)
            insecure, timeout = args.allow_insecure, args.timeout
            body = _tenant_move.export(base, tenant, token, Path(args.out),
                                       allow_insecure=insecure, timeout=timeout)  # fmt: skip
        else:
            source = Path(args.source)
            if not source.is_dir():
                raise ValueError(f"not an export folder: {args.source}")
            if args.remote:
                base, tenant, token = resolve(args, args.remote)
                moved = _tenant_move.import_remote(source, base, tenant, token,
                                                   allow_insecure=args.allow_insecure,
                                                   timeout=args.timeout)  # fmt: skip
                into = f"{base}/v1/tenants/{tenant}"
            else:
                from opentine.repository import Repo

                moved = _tenant_move.import_local(source, Repo.open(args.repo))
                into = Path(args.repo).as_posix()
            body = {"command": "tenant-import", "into": into, **moved}
    except Exception as exc:  # network, refusals, bad input: one clean error line
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(message, prefix="tine tenant: ")
    _print(args, body)


TENANT_COMMANDS = {"tenant": cmd_tenant}

__all__ = ["TENANT_COMMANDS", "add_tenant_parsers", "cmd_tenant"]
