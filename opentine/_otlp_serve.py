"""``tine serve --otlp``: OTLP/HTTP, OTLP/gRPC (0.48) or both, into one collector.

``--otlp-protocol http`` (the default) is the stdlib OTLP/HTTP receiver, loopback
only unless ``--insecure-dev-any-host``. ``grpc`` and ``both`` add the gRPC
receiver (``opentine[grpc]``) on ``--otlp-grpc-port`` (4317); off loopback it
requires TLS (``--cert``/``--key``) and ``--otlp-token-file``, with no
override (``docs/security/otlp-grpc-review.md``).
"""

from __future__ import annotations

import argparse
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

PROTOCOLS = ("http", "grpc", "both")


def add_otlp_grpc_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--otlp-protocol", choices=PROTOCOLS, default="http", help="OTLP transport(s) (http)"
    )
    parser.add_argument("--otlp-grpc-port", type=int, default=4317, help="OTLP/gRPC port (4317)")
    parser.add_argument(
        "--otlp-token-file", metavar="FILE", help="Bearer token OTLP/gRPC callers must send"
    )


def serve(args: Any, console: Any, loopback: Callable[[str], bool]) -> None:
    from opentine._cli_render import _save_run_receipt
    from opentine._otlp_collect import OtlpCollector
    from opentine._otlp_grpc import read_token, start_grpc, sweep_until
    from opentine._otlp_http import start

    protocol = getattr(args, "otlp_protocol", "http")
    local = loopback(args.host)
    if protocol != "grpc" and not (local or args.insecure_dev_any_host):
        raise SystemExit("--otlp is unauthenticated: loopback only unless --insecure-dev-any-host")
    if min(args.otlp_idle, args.max_body_mb) <= 0:
        raise SystemExit("--otlp-idle and --max-body-mb must be positive")
    token = read_token(getattr(args, "otlp_token_file", None))
    tls = None
    if protocol != "http":
        if bool(args.cert) != bool(args.key):
            raise SystemExit("OTLP/gRPC TLS needs both --cert and --key")
        if not local and not (args.cert and token):
            raise SystemExit("OTLP/gRPC off loopback requires TLS (--cert/--key) and a token")
        if args.cert:
            tls = (Path(args.key).read_bytes(), Path(args.cert).read_bytes())
    collector = OtlpCollector(
        lambda run: _save_run_receipt(run, None), idle=args.otlp_idle, report=console.print
    )
    limit = args.max_body_mb << 20
    stop, http, grpc_server = threading.Event(), None, None
    if protocol != "grpc":
        http = start(collector, args.host, args.otlp_port, max_bytes=limit)
        host, port = http.server_address[:2]
        console.print(f"OpenTine OTLP/HTTP receiver on http://{host}:{port} (/v1/traces, /v1/logs)")
    if protocol != "http":
        grpc_server, port = start_grpc(
            collector, args.host, args.otlp_grpc_port, max_bytes=limit, token=token, tls=tls
        )
        scheme = "grpcs" if tls else "grpc"
        console.print(f"OpenTine OTLP/gRPC receiver on {scheme}://{args.host}:{port}")
        if http is None:
            threading.Thread(target=sweep_until, args=(collector, stop), daemon=True).start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        if grpc_server is not None:
            grpc_server.stop(None)
        if http is not None:
            http.stop()
        else:
            collector.flush_all()


__all__ = ["PROTOCOLS", "add_otlp_grpc_args", "serve"]
