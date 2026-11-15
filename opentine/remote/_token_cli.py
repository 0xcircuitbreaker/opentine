"""``tine serve token mint|list|revoke``: scoped API tokens, offline on ``--root``.

The server need not be running: tokens live in ``<root>/auth.sqlite3``
(``_token_store``) and a running server reads them on every request, so a
revocation applies at once. ``mint`` prints the secret exactly once; only its
digest is stored. ``--json`` prints one ``tine-cli-serve-token-1`` document.
"""

from __future__ import annotations

import argparse
from typing import Any

SCHEMA = "tine-cli-serve-token/1"


def add_token_parser(actions: Any) -> argparse.ArgumentParser:
    token = actions.add_parser("token", help="Mint, list or revoke scoped API tokens (0.52)")
    verbs = token.add_subparsers(dest="token_action", metavar="VERB", required=True)
    mint = verbs.add_parser("mint", help="Mint a token; its secret is printed once")
    mint.add_argument("--access", choices=("read", "write"), default="read")
    mint.add_argument(
        "--ref",
        dest="refs",
        action="append",
        metavar="NAMESPACE",
        help="A ref (heads/main) or prefix (heads/ci/) it may reach; repeatable; '*' = all",
    )
    mint.add_argument("--ttl", default="90d", help="Lifetime: 900s, 12h, 30d (max 366d)")
    mint.add_argument("--label", default="", help="A note shown by list")
    listing = verbs.add_parser("list", help="The tenant's tokens (never their secrets)")
    revoke = verbs.add_parser("revoke", help="Revoke a token by id (idempotent)")
    revoke.add_argument("token_id", metavar="ID")
    for parser in (mint, listing, revoke):
        parser.add_argument("--root", default=argparse.SUPPRESS, help="Remote state directory")
        parser.add_argument("--tenant", default=argparse.SUPPRESS, help="Tenant namespace")
        parser.add_argument("--json", action="store_true", help="Print tine-cli-serve-token-1")
    return token


def cmd_token(args: argparse.Namespace, console: Any) -> None:
    from opentine._cli_json import emit
    from opentine.remote._token_store import TokenStore, parse_ttl

    verb = args.token_action
    store = TokenStore.at(args.root)
    secret = None
    try:
        if verb == "mint":
            ttl = parse_ttl(args.ttl)
            secret, record = store.mint(
                args.tenant, args.access, args.refs or ["*"], ttl=ttl, label=args.label
            )
            tokens = [record]
        elif verb == "list":
            tokens = store.list(args.tenant)
        else:
            tokens = [store.revoke(args.token_id, args.tenant)]
    except KeyError:
        raise SystemExit(f"no token {args.token_id} in tenant {args.tenant}") from None
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    if args.json:
        body = {"command": f"serve token {verb}", "schema": SCHEMA, "ok": True, "tokens": tokens}
        emit({**body, **({"token": secret} if secret else {})})
        return
    for item in tokens:
        refs = ",".join(item["refs"])
        console.print(
            f"{item['id']}  {item['state']:8} {item['access']:5} {refs}  "
            f"expires {item['expires_at']}",
            markup=False,
            highlight=False,
        )
    if secret:
        console.print(f"token (shown once): {secret}", markup=False, highlight=False)


__all__ = ["SCHEMA", "add_token_parser", "cmd_token"]
