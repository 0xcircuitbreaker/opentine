"""``tine serve ACTION``: the operator's offline maintenance verbs (see ``_admin``).

Without an action ``tine serve`` runs the server, exactly as before. With one, it
opens the same ``--root`` storage (decrypting with ``TINE_KMS_KEY``, as the
server does) and exits; no network listener is involved.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Any

ACTIONS = ("refs", "delete-ref", "associations", "delete-objects", "purge")


def _scoped(parser: argparse.ArgumentParser) -> None:
    # SUPPRESS keeps `tine serve --root R purge` working: an option given before
    # the action is not overwritten by the action parser's default.
    parser.add_argument("--root", default=argparse.SUPPRESS, help="Remote state directory")
    parser.add_argument("--tenant", default=argparse.SUPPRESS, help="Tenant namespace")


def add_admin_parsers(serve: argparse.ArgumentParser) -> None:
    actions = serve.add_subparsers(
        dest="admin_action",
        metavar="ACTION",
        help="Offline maintenance on --root instead of serving (no network listener)",
    )
    refs = actions.add_parser("refs", help="List the tenant's refs straight from storage")
    delete_ref = actions.add_parser("delete-ref", help="Delete a ref (compare-and-swap)")
    delete_ref.add_argument("name")
    delete_ref.add_argument("--expect", metavar="OID", help="Delete only if the ref targets OID")
    associations = actions.add_parser(
        "associations", help="List annotations/attestations naming an object, oldest first"
    )
    associations.add_argument("target", metavar="OID")
    delete_objects = actions.add_parser(
        "delete-objects", help="Delete objects that no ref reaches except as associations"
    )
    delete_objects.add_argument("oids", nargs="*", metavar="OID")
    delete_objects.add_argument("--from", dest="from_file", metavar="FILE", help="'-' for stdin")
    purge = actions.add_parser("purge", help="Delete objects no ref reaches")
    purge.add_argument(
        "--grace-seconds",
        type=float,
        default=3600.0,
        help="Keep unreferenced objects written this recently (default 3600)",
    )
    for parser in (delete_objects, purge):
        parser.add_argument("--dry-run", action="store_true", help="Report without deleting")
    for parser in (refs, delete_ref, associations, delete_objects, purge):
        _scoped(parser)


def _oids(args: argparse.Namespace) -> list[str]:
    oids = list(args.oids)
    if args.from_file:
        handle = sys.stdin if args.from_file == "-" else open(args.from_file, encoding="utf-8")
        with handle:
            oids.extend(line.strip() for line in handle if line.strip())
    return oids


def cmd_serve_admin(args: argparse.Namespace, console: Any) -> None:
    from opentine.remote._admin import RemoteAdmin

    admin = RemoteAdmin.open(args.root)
    action = args.admin_action
    if action == "refs":
        result: Any = {"refs": admin.refs(args.tenant)}
    elif action == "delete-ref":
        deleted = admin.delete_ref(args.tenant, args.name, args.expect)
        result = {"deleted": deleted, "name": args.name}
    elif action == "associations":
        result = {"associations": admin.associations(args.tenant, args.target)}
    elif action == "delete-objects":
        result = asdict(admin.delete_objects(args.tenant, _oids(args), dry_run=args.dry_run))
    else:
        purge = admin.purge(args.tenant, grace_seconds=args.grace_seconds, dry_run=args.dry_run)
        result = asdict(purge)
    print(json.dumps(result, indent=2, sort_keys=True))
    if action == "delete-ref" and not result["deleted"]:
        raise SystemExit(1)
