"""``tine mcp-proxy``: record an MCP session by standing between client and server.

``tine mcp-proxy -- CMD [ARGS...]`` spawns the MCP server CMD and relays this
process's stdin/stdout to it (stdio transport). ``tine mcp-proxy --http-upstream
URL --listen 127.0.0.1:PORT`` relays Streamable HTTP to URL instead. Every
JSON-RPC exchange becomes a ``tool`` step, redacted before it is hashed or
stored; the relayed bytes are never changed. The run is saved as it grows, to
``--save PATH`` or ``.tine_runs/mcp-proxy-<time>-<pid>.tine``, and ``--repo``
installs the finished run into a repository. Messages go to stderr: stdout is
the protocol channel.
"""

from __future__ import annotations

import argparse
import os
import signal
import threading
import time
from pathlib import Path
from typing import Any, NoReturn

from rich.console import Console

from opentine._cli_common import _runs_dir, _terminal
from opentine._cli_errors import fail
from opentine._cli_flags import _require_output_slot
from opentine.redaction import redact_text

err = Console(stderr=True, emoji=False)


def add_mcp_proxy_parser(sub: Any) -> None:
    proxy = sub.add_parser(
        "mcp-proxy", help="Relay an MCP session (stdio or Streamable HTTP) and record it"
    )
    proxy.add_argument("--http-upstream", metavar="URL", help="Relay Streamable HTTP to URL")
    proxy.add_argument(
        "--listen", metavar="HOST:PORT", default="127.0.0.1:0", help="HTTP bind address"
    )
    proxy.add_argument(
        "--allow-non-loopback", action="store_true", help="Permit a non-loopback --listen"
    )
    proxy.add_argument("--save", metavar="PATH", help="Write the run here (updated as it grows)")
    proxy.add_argument("--force", action="store_true", help="Replace an existing --save file")
    proxy.add_argument("--repo", metavar="PATH", help="Also install the run into this repository")
    proxy.add_argument("--ref", metavar="REF", help="Ref the --repo install advances")
    proxy.add_argument("cmd", nargs=argparse.REMAINDER, help="The MCP server command, after --")


def _fail(message: str) -> NoReturn:
    fail(message, prefix="mcp-proxy")


def _address(listen: str, allow: bool) -> tuple[str, int]:
    from opentine._mcp_proxy_http import is_loopback

    host, _, port = listen.rpartition(":")
    host = host.strip("[]") or "127.0.0.1"
    if not port.isdigit():
        _fail(f"--listen needs HOST:PORT, got {listen!r}")
    if not allow and not is_loopback(host):
        _fail("--listen must be a loopback address; pass --allow-non-loopback to override")
    return host, int(port)


def _serve_http(args: argparse.Namespace, command: list[str], recorder: Any) -> int:
    import subprocess

    from opentine import _mcp_proxy_http

    server = _mcp_proxy_http.start(args.address, args.http_upstream, recorder)
    host = server.server_address[0]
    err.print(f"mcp-proxy: listening on http://{host}:{server.port}/ -> {args.http_upstream}")
    try:
        if command:
            return subprocess.call(command)
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0
    finally:
        server.shutdown()
        server.server_close()


def cmd_mcp_proxy(args: argparse.Namespace) -> None:
    from opentine import _mcp_proxy_stdio
    from opentine._mcp_proxy_record import McpRecorder

    command = list(args.cmd or [])
    command = command[1:] if command[:1] == ["--"] else command
    if not command and not args.http_upstream:
        _fail("Name the MCP server: tine mcp-proxy -- CMD [ARGS...] or --http-upstream URL")
    if args.ref and not args.repo:
        _fail("--ref needs --repo")
    if args.http_upstream:
        args.address = _address(args.listen, args.allow_non_loopback)
    if args.save:
        _require_output_slot(Path(args.save), args.force)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    output = Path(args.save or _runs_dir() / f"mcp-proxy-{stamp}-{os.getpid()}.tine")
    transport = "http" if args.http_upstream else "stdio"
    recorder = McpRecorder(output, command or [args.http_upstream], transport, err.print)
    if threading.current_thread() is threading.main_thread() and hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        if args.http_upstream:
            code = _serve_http(args, command, recorder)
        else:
            code = _mcp_proxy_stdio.relay(command, recorder)
    except OSError as exc:
        err.print(f"[red]Cannot run {redact_text(command[0])}:[/] {exc.strerror or exc}")
        code = 127
    except KeyboardInterrupt:
        code = 130
    recorder.close(code)
    err.print(f"mcp-proxy: {recorder.steps} step(s) saved to {_terminal(output)}")
    if recorder.dropped:
        err.print(f"mcp-proxy: {recorder.dropped} message(s) not recorded (queue full)")
    if args.repo:
        _install(output, args.repo, args.ref or "heads/main")
    raise SystemExit(code)


def _install(output: Path, repo_path: str, ref: str) -> None:
    from opentine._artifact_v4_repo import install_v4
    from opentine._cli_import_v4 import sniff_v4
    from opentine.repo import Repo

    try:
        data = sniff_v4(str(output))
        if data is None:
            raise ValueError("the saved run is not a format v4 artifact")
        result = install_v4(Repo.open(repo_path), data, ref=ref)
    except (KeyError, OSError, RecursionError, ValueError) as exc:
        err.print(f"[red]mcp-proxy: install into {_terminal(repo_path)} failed:[/] {exc}")
        return
    err.print(f"mcp-proxy: installed {result['root']} into {_terminal(repo_path)} at {ref}")


COMMANDS = {"mcp-proxy": cmd_mcp_proxy}

__all__ = ["COMMANDS", "add_mcp_proxy_parser", "cmd_mcp_proxy"]
