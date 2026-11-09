"""Resolve a remote name or URL to ``(base, tenant, token)`` for the 0.46 remote-aware verbs.

``tine share``, ``tine open``, ``tine repo-search --remote`` and ``tine remote
login`` take a remote the way ``tine watch`` does: a URL, or a name from the
repository's trusted ``.tine/porcelain.json`` (``tine remote add``). The token
comes from ``--token-file``, the remote's ``token_file`` (where ``tine remote
login`` stores it) or ``TINE_REMOTE_TOKEN``; it is never printed.
"""

from __future__ import annotations

import argparse
from typing import Any
from urllib.parse import quote


def add_remote_args(parser: argparse.ArgumentParser, *, name: str = "--remote") -> None:
    parser.add_argument(name, default=None, metavar="REMOTE", help="Remote name or URL")
    parser.add_argument("--tenant")
    parser.add_argument("--token", help=argparse.SUPPRESS)
    parser.add_argument("--token-file", metavar="PATH")
    parser.add_argument("--allow-insecure", action="store_true")
    parser.add_argument("--timeout", type=float, default=30.0, help="Per-request seconds")


def entry_for(repo_path: str, name: str) -> dict[str, Any] | None:
    from opentine import _porcelain_config as porcelain
    from opentine._cli_du import _repo

    try:
        path = _repo(repo_path).path
    except (KeyError, OSError, ValueError):
        return None
    return porcelain.remote(path, name)  # an untrusted file says so


def resolve(args: argparse.Namespace, target: str | None) -> tuple[str, str, str | None]:
    """``(base, tenant, token)`` for *target* (default ``origin``)."""
    from opentine._repo_cli_token import _token
    from opentine.repository._http import split_remote

    target = target or "origin"
    if "://" not in target:
        entry = entry_for(getattr(args, "repo", "."), target)
        if entry is None:
            raise ValueError(f"no such remote: {target} (give a URL or `tine remote add`)")
        target = entry["url"]
        args.tenant = args.tenant or entry.get("tenant")
        if not args.token and not args.token_file:
            args.token_file = entry.get("token_file")
    base, tenant = split_remote(target, args.tenant)
    return base, tenant, _token(args)


def tenant_path(tenant: str, resource: str) -> str:
    return f"/v1/tenants/{quote(tenant, safe='')}/{resource}"


def call(args, base: str, token, method: str, path: str, **kwargs) -> dict[str, Any]:
    """One JSON request; a 404 (the server's uniform answer) becomes ``KeyError``."""
    from opentine.repository._http import client, request_json

    with client(base, token, allow_insecure=args.allow_insecure, timeout=args.timeout) as http:
        status, body = request_json(
            http, method, path, allowed=(200, 201, 404), max_seconds=args.timeout, **kwargs
        )
    if status == 404:
        raise KeyError("not found (or not visible to this token)")
    return body


__all__ = ["add_remote_args", "call", "entry_for", "resolve", "tenant_path"]
