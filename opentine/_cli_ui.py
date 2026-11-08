"""``tine ui [RUN] [--port N] [--open]``: a read-only local run viewer.

Serves the viewer assets in ``opentine/data/ui`` (built from ``ts/run-viewer``)
and a redacted JSON API on 127.0.0.1 only. Nothing is written and no outbound
connection is made. With RUN it shows that run; otherwise every run in the
runs directory (bounded by the CLI scan limit).
"""

from __future__ import annotations

import argparse
from itertools import islice
from pathlib import Path
from typing import Any

from opentine._cli_common import MAX_CLI_SCAN_RUNS, _find_run, _runs_dir, _terminal, console


def add_ui_parser(sub: Any) -> None:
    ui = sub.add_parser("ui", help="Browse runs in a read-only local web viewer (127.0.0.1)")
    ui.add_argument("run_id", metavar="RUN", nargs="?", help="Run id, prefix, or .tine path")
    ui.add_argument("--port", type=int, default=0, help="Port on 127.0.0.1 (default: any free)")
    ui.add_argument("--open", action="store_true", help="Open the viewer in a web browser")


def _paths(run_id: str | None) -> list[Path]:
    if run_id:
        path = _find_run(run_id)
        if not path:
            console.print(f"[red]Run not found: {_terminal(run_id)}[/]")
            raise SystemExit(1)
        return [path]
    root = _runs_dir()
    return sorted(islice(root.glob("*.tine"), MAX_CLI_SCAN_RUNS)) if root.is_dir() else []


def cmd_ui(args: argparse.Namespace) -> None:
    from opentine._ui_server import Catalog, make_server

    if not 0 <= args.port <= 65535:
        console.print(f"[red]--port must be 0..65535, got {args.port}[/]")
        raise SystemExit(2)
    catalog = Catalog(_paths(args.run_id))
    catalog.runs()  # read every artifact once, before the first page asks
    try:
        server = make_server(catalog, args.port)
    except OSError as exc:
        console.print(f"[red]Cannot listen on 127.0.0.1:{args.port}:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    console.print(f"tine ui serving {url} (read-only; Ctrl-C to stop)")
    if args.open:
        import webbrowser

        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


COMMANDS = {"ui": cmd_ui}

__all__ = ["COMMANDS", "add_ui_parser", "cmd_ui"]
