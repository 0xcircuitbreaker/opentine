"""``tine mcp-proxy``: record an MCP session by standing between client and server.

``tine mcp-proxy -- CMD [ARGS...]`` spawns the MCP server CMD and relays this
process's stdin/stdout to it (stdio transport). ``tine mcp-proxy --http-upstream
URL --listen 127.0.0.1:PORT`` relays Streamable HTTP to URL instead. Every
JSON-RPC exchange becomes a ``tool`` step, redacted before it is hashed or
stored; the relayed bytes are never changed. The run is saved as it grows, to
``--save PATH`` or ``.tine_runs/mcp-proxy-<time>-<pid>.tine``, and ``--repo``
installs the finished run into a repository. Messages go to stderr: stdout is
the protocol channel.

0.63: ``--monitor CONFIG --monitor-repo PATH --monitor-key KEY`` puts an
inline monitor on ``tools/call`` (:mod:`opentine._monitor_mcp`, docs/MONITORS.md):
advisory by default, a blocking gate only when the config says ``mode = "gate"``.
0.69: ``--budget SUBJECT --budget-key KEY`` refuses ``tools/call`` once the
subject's budget is reached (:mod:`opentine._budget_gate`, docs/BUDGETS.md).
0.72: ``--organism-gate`` refuses a ``tools/call`` that loads a tagged model
organism without an approval for ``--organism-run`` (docs/MODEL_ORGANISMS.md).
0.88: ``--tool-defs block`` refuses calls to a tool whose definition is not the
session pin (:mod:`opentine._mcp_tool_guard`); recording it is always on.
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
    proxy.add_argument("--monitor", metavar="CONFIG", help="Monitor config (docs/MONITORS.md)")
    proxy.add_argument("--monitor-repo", metavar="PATH",
                       help="Repository the signed verdicts go to (default: --repo)")  # fmt: skip
    proxy.add_argument("--monitor-key", metavar="KEY", help="Ed25519 key that signs verdicts")
    proxy.add_argument("--monitor-agent", metavar="NAME", help="Agent name stop tokens match")
    proxy.add_argument("--budget", metavar="SUBJECT",
                       help="Refuse tools/call once SUBJECT's budget is reached")  # fmt: skip
    proxy.add_argument("--tool-defs", choices=("advisory", "block"), default="advisory",
                       help="Refuse calls to a tool whose definition changed (block)")  # fmt: skip
    proxy.add_argument("--budget-key", metavar="KEY", help="Ed25519 key that signs budget flags")
    proxy.add_argument("--organism-gate", action="store_true",
                       help="Refuse loading a tagged model organism without approval")  # fmt: skip
    proxy.add_argument("--organism-run", metavar="RUN", help="The run approvals must name")
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


def _guard(args: argparse.Namespace, session: str) -> Any:
    """The monitor guard ``--monitor`` asks for, or ``None``."""
    if not args.monitor:
        return None
    from opentine._key_hygiene import ed25519_private
    from opentine._monitor_gate import Gate
    from opentine._monitor_mcp import McpGuard
    from opentine._monitors import load
    from opentine.repo import Repo

    where = args.monitor_repo or args.repo
    if not where or not args.monitor_key:
        _fail("--monitor needs --monitor-repo (or --repo) and --monitor-key: verdicts are signed")
    try:
        config = load(args.monitor)
        store = Repo.open(where)
        from opentine._integrity_defaults import pin  # 0.85: the monitor config is pinned

        pin(Path(store.path).parent, args.monitor, "monitor")
        gate = Gate(config, repo=store, key=ed25519_private(args.monitor_key),
                    session=session, agent=args.monitor_agent)  # fmt: skip
    except (OSError, ValueError) as exc:
        _fail(f"monitor: {exc}")
    err.print(f"mcp-proxy: monitor {config['monitor'].identity['id']} ({config['mode']})")
    return McpGuard(gate, err.print)


def _budget(args: argparse.Namespace, inner: Any) -> Any:
    """The budget guard ``--budget`` asks for (wrapping *inner*), else *inner*."""
    if not getattr(args, "budget", None):
        return inner
    from opentine._budget_gate import BudgetMcpGuard
    from opentine._budget_policy import subject
    from opentine._key_hygiene import ed25519_private
    from opentine.repo import Repo

    where = args.monitor_repo or args.repo
    if not where or not args.budget_key:
        _fail("--budget needs --repo (or --monitor-repo) and --budget-key: flags are signed")
    try:
        guard = BudgetMcpGuard(Repo.open(where), subject(args.budget),
                               ed25519_private(args.budget_key), inner)  # fmt: skip
    except (OSError, ValueError) as exc:
        _fail(f"budget: {exc}")
    err.print(f"mcp-proxy: budget {args.budget}")
    return guard


def _organism(args: argparse.Namespace, inner: Any, session: str) -> Any:
    """The model-organism guard ``--organism-gate`` asks for (wrapping *inner*)."""
    if not getattr(args, "organism_gate", False):
        return inner
    from opentine._organism_gate import OrganismMcpGuard
    from opentine.repo import Repo

    where = args.monitor_repo or args.repo
    if not where:
        _fail("--organism-gate needs --repo (or --monitor-repo): the tag registry lives there")
    try:
        repo = Repo.open(where)
    except (OSError, ValueError):
        repo = None  # an unreadable registry refuses every tools/call (fail closed)
    err.print(f"mcp-proxy: model-organism gate (run {args.organism_run or session})")
    return OrganismMcpGuard(repo, args.organism_run or session, inner)


def _serve_http(args: argparse.Namespace, command: list[str], recorder: Any) -> int:
    import subprocess

    from opentine import _mcp_proxy_http

    server = _mcp_proxy_http.start(args.address, args.http_upstream, recorder, args.guard)
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
    from opentine._mcp_tool_guard import cli_wrap as wrap_tool_defs

    command = list(args.cmd or [])
    command = command[1:] if command[:1] == ["--"] else command
    if not command and not args.http_upstream:
        _fail("Name the MCP server: tine mcp-proxy -- CMD [ARGS...] or --http-upstream URL")
    if args.ref and not args.repo:
        _fail("--ref needs --repo")
    args.address = _address(args.listen, args.allow_non_loopback) if args.http_upstream else None
    if args.save:
        _require_output_slot(Path(args.save), args.force)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    output = Path(args.save or _runs_dir() / f"mcp-proxy-{stamp}-{os.getpid()}.tine")
    transport = "http" if args.http_upstream else "stdio"
    recorder = McpRecorder(output, command or [args.http_upstream], transport, err.print)
    monitor = _guard(args, f"mcp-{stamp}-{os.getpid()}")
    args.guard = _organism(args, _budget(args, monitor), f"mcp-{stamp}-{os.getpid()}")
    args.guard = wrap_tool_defs(args, args.guard)  # 0.88: outermost guard
    if monitor is not None:
        recorder.run.metadata["monitor"] = {**monitor.gate.monitor.identity,
                                            "mode": monitor.gate.config["mode"]}  # fmt: skip
    if threading.current_thread() is threading.main_thread() and hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        if args.http_upstream:
            code = _serve_http(args, command, recorder)
        else:
            code = _mcp_proxy_stdio.relay(command, recorder, args.guard)
    except OSError as exc:
        err.print(f"[red]Cannot run {redact_text(command[0])}:[/] {exc.strerror or exc}")
        code = 127
    except KeyboardInterrupt:
        code = 130
    if args.guard is not None:
        args.guard.close()
    if getattr(args.guard, "denied", 0):
        err.print(f"mcp-proxy: budget refused {args.guard.denied} tools/call request(s)")
    if monitor is not None:
        counts = monitor.gate.counts
        err.print(f"mcp-proxy: monitor forwarded {counts['forward']}, replaced "
                  f"{counts['replace']}, blocked {counts['block']}")  # fmt: skip
    recorder.close(code)
    err.print(f"mcp-proxy: {recorder.steps} step(s) saved to {_terminal(output)}")
    if not recorder.witnessed:
        err.print("mcp-proxy: unwitnessed (assurance T0): run `tine proxy keygen` to sign runs")
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
