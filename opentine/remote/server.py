"""Reference self-hosted remote construction and TLS server entry point."""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import threading
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from opentine.remote.app import RemoteApp
from opentine.remote.backend import FilesystemObjectStore, SQLiteBackend
from opentine.remote.interfaces import Identity, IdentityProvider, KeyProvider
from opentine.remote.security import (
    LocalKeyProvider,
    RoleAuthorizationPolicy,
    StaticTokenIdentityProvider,
)
from opentine.remote.service import RemoteService


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    request_queue_size = 64
    max_workers = 16
    request_deadline = 60
    ssl_context: ssl.SSLContext | None = None

    def __init__(self, *args, **kwargs):
        self._request_slots = threading.BoundedSemaphore(self.max_workers)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address) -> None:
        self._request_slots.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def get_request(self):
        request, address = super().get_request()
        if self.ssl_context is None:
            return request, address
        try:
            wrapped = self.ssl_context.wrap_socket(
                request, server_side=True, do_handshake_on_connect=False
            )
        except BaseException:
            request.close()
            raise
        return wrapped, address

    def process_request_thread(self, request, client_address) -> None:
        def expire() -> None:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        deadline = threading.Timer(self.request_deadline, expire)
        deadline.daemon = True
        deadline.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            deadline.join()
            self._request_slots.release()


class TimeoutRequestHandler(WSGIRequestHandler):
    #: Per-connection inactivity timeout; the server also has an absolute deadline.
    timeout = 30


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
    parser.add_argument("--timeout", type=int, default=30, help="Per-connection socket timeout (s)")
    parser.add_argument(
        "--request-deadline", type=int, default=60, help="Absolute request deadline (s)"
    )
    parser.add_argument("--max-body-mb", type=int, default=16, help="Max single request size (MiB)")
    parser.add_argument(
        "--max-upload-mb", type=int, default=256, help="Max resumed pack size (MiB)"
    )
    parser.add_argument("--max-connections", type=int, default=16, help="Maximum worker threads")
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


def cmd_serve(args: argparse.Namespace, console: Any) -> None:
    token = os.environ.get(args.token_env)
    if not token:
        raise SystemExit(f"{args.token_env} must contain the development bearer token")
    if len(token.encode("utf-8")) < 16:
        raise SystemExit(f"{args.token_env} must contain at least 16 bytes of token material")
    if not args.insecure_dev and not (args.cert and args.key):
        raise SystemExit("TLS --cert and --key are required unless --insecure-dev is explicit")
    if (
        min(
            args.timeout,
            args.request_deadline,
            args.max_body_mb,
            args.max_upload_mb,
            args.max_connections,
        )
        < 1
    ):
        raise SystemExit("timeout and server limits must be positive")
    identities = StaticTokenIdentityProvider(
        {token: Identity("development", args.tenant, (args.role,))}
    )
    application = reference_app(
        args.root,
        identities=identities,
        max_request_bytes=args.max_body_mb * 1024 * 1024,
        max_upload_bytes=args.max_upload_mb * 1024 * 1024,
        migrate_legacy_audit=args.migrate_legacy_audit,
        reanchor_audit_head=args.reanchor_audit_head,
    )
    handler = type("_Handler", (TimeoutRequestHandler,), {"timeout": args.timeout})
    server_class = type(
        "_Server",
        (ThreadingWSGIServer,),
        {"max_workers": args.max_connections, "request_deadline": args.request_deadline},
    )
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
