"""Reference self-hosted remote construction and TLS server entry point."""

from __future__ import annotations

import argparse
import ipaddress
import os
import ssl
from pathlib import Path
from typing import Any
from wsgiref.simple_server import make_server

from opentine.remote._admin_cli import add_admin_parsers, cmd_serve_admin
from opentine.remote._http_server import ThreadingWSGIServer, TimeoutRequestHandler
from opentine.remote.app import RemoteApp
from opentine.remote.backend import FilesystemObjectStore, SQLiteBackend
from opentine.remote.interfaces import Identity, IdentityProvider, KeyProvider
from opentine.remote.security import (
    LocalKeyProvider,
    RoleAuthorizationPolicy,
    StaticTokenIdentityProvider,
)
from opentine.remote.service import RemoteService


def _loopback(host: str) -> bool:
    if host.lower() in {"localhost", "localhost."}:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def reference_app(
    root: str | Path,
    *,
    identities: IdentityProvider,
    keys: KeyProvider | None = None,
    authorization=None,
    admission=None,
    audit_key: bytes | None = None,
    migrate_legacy_audit: bool = False,
    reanchor_audit_head: str | None = None,
    max_request_bytes: int = 16 * 1024 * 1024,
    max_upload_bytes: int = 256 * 1024 * 1024,
) -> RemoteApp:
    state = Path(root).resolve()
    key_provider = keys or LocalKeyProvider.from_env()
    objects = FilesystemObjectStore(state / "objects", key_provider)
    chain_key = audit_key
    if chain_key is None:
        derive = getattr(key_provider, "derive_audit_key", None)
        if not callable(derive):
            raise RuntimeError("key provider must derive an audit key or receive audit_key")
        chain_key = derive()
    index = SQLiteBackend(
        state / "metadata.sqlite3",
        audit_key=chain_key,
        migrate_legacy_audit=migrate_legacy_audit,
        reanchor_audit_head=reanchor_audit_head,
    )
    service = RemoteService(
        objects,
        index,
        identities,
        authorization or RoleAuthorizationPolicy(),
        admission=admission,
    )
    return RemoteApp(
        service,
        state,
        max_request_bytes=max_request_bytes,
        max_upload_bytes=max_upload_bytes,
    )


def add_serve_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("serve", help="Run the minimal self-hosted v3 remote")
    parser.add_argument("--root", default=".tine-remote")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--tenant", default=os.environ.get("TINE_REMOTE_TENANT", "default"))
    parser.add_argument("--role", choices=("reader", "writer", "admin"), default="writer")
    parser.add_argument("--token-env", default="TINE_REMOTE_TOKEN")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--insecure-dev", action="store_true")
    parser.add_argument(
        "--insecure-dev-any-host",
        action="store_true",
        help="Allow --insecure-dev (plaintext bearer tokens) on a non-loopback --host",
    )
    parser.add_argument(
        "--writer-promotes",
        action="store_true",
        help="Let writers move promotions/* and existing tags/* (admin-only by default)",
    )
    parser.add_argument("--timeout", type=int, default=30, help="Per-connection socket timeout (s)")
    parser.add_argument(
        "--header-timeout", type=int, default=10, help="Seconds to send TLS + request headers"
    )
    parser.add_argument(
        "--request-deadline", type=int, default=60, help="Absolute request deadline (s)"
    )
    parser.add_argument("--max-body-mb", type=int, default=16, help="Max single request size (MiB)")
    parser.add_argument(
        "--max-upload-mb", type=int, default=256, help="Max resumed pack size (MiB)"
    )
    parser.add_argument("--max-connections", type=int, default=16, help="Maximum worker threads")
    parser.add_argument(
        "--max-connections-per-peer", type=int, help="Worker threads one peer may hold (half)"
    )
    parser.add_argument(
        "--migrate-legacy-audit",
        action="store_true",
        help="One-time trust-on-migration for pre-HMAC audit rows",
    )
    parser.add_argument(
        "--reanchor-audit-head",
        metavar="SHA256",
        help="Recover a verified chain only when its computed head equals SHA256",
    )
    add_admin_parsers(parser)


def cmd_serve(args: argparse.Namespace, console: Any) -> None:
    if getattr(args, "admin_action", None):
        return cmd_serve_admin(args, console)
    token = os.environ.get(args.token_env)
    if not token:
        raise SystemExit(f"{args.token_env} must contain the development bearer token")
    if len(token.encode("utf-8")) < 16:
        raise SystemExit(f"{args.token_env} must contain at least 16 bytes of token material")
    if not args.insecure_dev and not (args.cert and args.key):
        raise SystemExit("TLS --cert and --key are required unless --insecure-dev is explicit")
    if args.insecure_dev and not (_loopback(args.host) or args.insecure_dev_any_host):
        raise SystemExit(
            "--insecure-dev sends bearer tokens in plaintext: it serves loopback only "
            "unless --insecure-dev-any-host is also given"
        )
    peer_limit = args.max_connections_per_peer
    limits = (args.timeout, args.header_timeout, args.request_deadline, args.max_body_mb)
    limits += (args.max_upload_mb, args.max_connections, peer_limit or 1)
    if min(limits) < 1:
        raise SystemExit("timeout and server limits must be positive")
    identities = StaticTokenIdentityProvider(
        {token: Identity("development", args.tenant, (args.role,))}
    )
    application = reference_app(
        args.root,
        identities=identities,
        authorization=RoleAuthorizationPolicy(writer_promotes=args.writer_promotes),
        max_request_bytes=args.max_body_mb * 1024 * 1024,
        max_upload_bytes=args.max_upload_mb * 1024 * 1024,
        migrate_legacy_audit=args.migrate_legacy_audit,
        reanchor_audit_head=args.reanchor_audit_head,
    )
    handler_limits = {"timeout": args.timeout, "header_timeout": args.header_timeout}
    handler = type("_Handler", (TimeoutRequestHandler,), handler_limits)
    server_limits = {"max_workers": args.max_connections, "max_per_peer": peer_limit}
    server_limits["request_deadline"] = args.request_deadline
    server_class = type("_Server", (ThreadingWSGIServer,), server_limits)
    server = make_server(
        args.host,
        args.port,
        application,
        server_class=server_class,
        handler_class=handler,
    )
    scheme = "http"
    if not args.insecure_dev:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.cert, args.key)
        server.ssl_context = context
        scheme = "https"
    console.print(f"OpenTine remote listening on {scheme}://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
