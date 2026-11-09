"""``tine share create|revoke|list`` (verb ``share-link``) and ``tine open`` (0.46).

``share create RUN`` asks the remote (``caps.share``) for a read-only link bound
to one run that expires (``--ttl``, default 7 days) and can be revoked. The token
is shown once, on stdout, and never logged; ``share list`` shows ids, never
tokens. ``tine open RUN`` prints (and, on a terminal, opens) the run's page in the
web app: ``--web-url``, else ``TINE_WEB_URL``, else the ``web.url`` porcelain
setting, else the remote's own URL.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Any
from urllib.parse import quote

from opentine._cli_remote_target import add_remote_args, call, resolve, tenant_path

_TTL = re.compile(r"^(\d+)([smhd]?)$")
_UNIT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def ttl_seconds(text: str) -> int:
    match = _TTL.match(text.strip())
    if not match:
        raise argparse.ArgumentTypeError("--ttl is a number with an optional s/m/h/d suffix")
    return int(match.group(1)) * _UNIT[match.group(2)]


def add_share_parsers(sub: argparse._SubParsersAction) -> None:
    share = sub.add_parser("share-link", help="Create, revoke or list a remote's share links")
    actions = share.add_subparsers(dest="share_action", required=True)
    create = actions.add_parser("create", help="A read-only, expiring link to one run")
    create.add_argument("run", help="Run oid, ref or short id (resolved in --repo)")
    create.add_argument("--ttl", type=ttl_seconds, default=7 * 86400, help="e.g. 3600, 12h, 7d")
    revoke = actions.add_parser("revoke", help="Revoke a share link by id")
    revoke.add_argument("share_id")
    listing = actions.add_parser("list", help="List share links (ids, never tokens)")
    listing.add_argument("--run", help="Only links to this run")
    for parser in (create, revoke, listing):
        parser.add_argument("--repo", default=".")
        add_remote_args(parser)
        parser.add_argument("--json", action="store_true")
    opener = sub.add_parser("open", help="Open a run's page in the web app")
    opener.add_argument("run", help="Run oid, ref or short id (resolved in --repo)")
    opener.add_argument("--repo", default=".")
    opener.add_argument("--remote", default=None, metavar="REMOTE")
    opener.add_argument("--tenant")
    opener.add_argument("--web-url", metavar="URL", help="Base URL of the web app")
    opener.add_argument("--print", dest="print_only", action="store_true", help="Do not open")
    opener.add_argument("--json", action="store_true")


def _run(args, value: str) -> str:
    from opentine.kernel import OID_RE

    if OID_RE.match(value):
        return value
    from opentine._repo_cli_write import _run_oid
    from opentine.repository import Repo

    return _run_oid(Repo.open(args.repo), value)


def _emit(args, body: dict[str, Any], text: str) -> None:
    if args.json:
        from opentine._cli_json import emit

        emit({"command": body.pop("command"), "schema": "tine-cli-share/1", **body})
    else:
        print(text)


def cmd_share_link(args: argparse.Namespace) -> None:
    from opentine._cli_errors import fail

    try:
        base, tenant, token = resolve(args, args.remote)
        action = args.share_action
        if action == "create":
            run = _run(args, args.run)
            row = call(args, base, token, "POST", tenant_path(tenant, "shares"),
                       json={"run": run, "ttl": args.ttl})  # fmt: skip
            url = f"{base}/v1/share/{row.get('token')}"
            body = {"command": "share", "action": "create", "share": row, "url": url}
            _emit(args, body, f"{url}\nshare {row.get('id')} expires {row.get('expires')}")
        elif action == "revoke":
            path = tenant_path(tenant, f"shares/{quote(args.share_id, safe='')}")
            row = call(args, base, token, "DELETE", path)
            _emit(args, {"command": "share", "action": "revoke", "share": row},
                  f"revoked share {row.get('id')}")  # fmt: skip
        else:
            params = {"run": _run(args, args.run)} if args.run else None
            rows = call(args, base, token, "GET", tenant_path(tenant, "shares"), params=params)
            shares = rows.get("shares") or []
            lines = [f"{r['id']}\t{r['state']}\t{r['run']}\t{r['expires']}" for r in shares]
            _emit(args, {"command": "share", "action": "list", "shares": shares},
                  "\n".join(lines) or "no share links")  # fmt: skip
    except Exception as exc:  # network, refusals, bad input: one clean error line
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(message, prefix="tine share: ")


def web_url(args) -> tuple[str, str]:
    """``(web base, tenant)`` for ``tine open``."""
    from opentine import _porcelain_config as porcelain
    from opentine._cli_remote_target import entry_for
    from opentine.repository._http import split_remote

    remote = args.remote or "origin"
    entry = entry_for(args.repo, remote) if "://" not in remote else {"url": remote}
    tenant = args.tenant or (entry or {}).get("tenant")
    web = args.web_url or os.environ.get("TINE_WEB_URL")
    if not web:
        try:
            from opentine._cli_du import _repo

            path = _repo(args.repo).path  # a cloned, unreviewed file must not pick the page
            web = porcelain.effective(path).get("web.url") if porcelain.trusted(path) else None
        except (KeyError, OSError, ValueError):
            web = None
    if entry is None and not web:
        raise ValueError(f"no such remote: {remote}; pass --web-url or --remote URL")
    base, tenant = split_remote(entry["url"], tenant) if entry else ("", tenant or "")
    if not tenant:
        raise ValueError("tenant is required (--tenant, or the remote's tenant)")
    return (web or base).rstrip("/"), tenant


def cmd_open(args: argparse.Namespace) -> None:
    from opentine._cli_errors import fail

    try:
        web, tenant = web_url(args)
        run = _run(args, args.run)
    except Exception as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(message, prefix="tine open: ")
    url = f"{web}/{quote(tenant, safe='')}/runs/{quote(run, safe=':')}"
    if args.json:
        from opentine._cli_json import emit

        emit({"command": "open", "run": run, "tenant": tenant, "url": url})
        return
    print(url)
    if not args.print_only and sys.stdout.isatty():
        import webbrowser

        webbrowser.open(url)


SHARE_COMMANDS = {"share-link": cmd_share_link, "open": cmd_open}

__all__ = ["SHARE_COMMANDS", "add_share_parsers", "cmd_open", "cmd_share_link", "ttl_seconds"]
