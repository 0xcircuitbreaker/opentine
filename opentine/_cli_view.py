"""``tine view RUN [-o FILE.html] [--open]``: write a run as one static HTML page.

The page is self-contained (no network request, no script) and deterministic,
so it can be attached to an issue or archived where opentine is not installed.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._cli_common import _cost_str, _terminal, console
from opentine._codec_io import atomic_write_bytes


def add_view_parser(sub: Any) -> None:
    view = sub.add_parser("view", help="Write a run as one self-contained HTML page")
    view.add_argument("run_id", metavar="RUN", help="Run id, prefix, or .tine path")
    view.add_argument(
        "-o", "--output", metavar="FILE", help="HTML file to write (default: RUN-ID.html)"
    )
    view.add_argument("--open", action="store_true", help="Open the page in a web browser")


def cmd_view(args: argparse.Namespace) -> None:
    from opentine._cli_execute import _loaded_run
    from opentine._view_html import render_run

    _, run = _loaded_run(args.run_id)
    page = render_run(run, cost=_cost_str(run.total_cost))
    target = Path(args.output or f"{run.id[:12]}.html")
    try:
        atomic_write_bytes(target, page.encode("utf-8"))
    except OSError as exc:
        console.print(f"[red]Cannot write {_terminal(target)}:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    console.print(f"Wrote {_terminal(target)}")
    if args.open:
        import webbrowser

        webbrowser.open(target.resolve().as_uri())


COMMANDS = {"view": cmd_view}

__all__ = ["COMMANDS", "add_view_parser", "cmd_view"]
