"""``tine export RUN --format entire --output REPO``: a run as an Entire checkpoint.

``--output`` names the git repository the checkpoint ref is written into (the
layout is :mod:`opentine._entire_export`'s); ``tine import REPO --format
entire`` reads it back. The run is redacted on the way out, exactly as every
other export format is. Flags that only mean something for a document or an
OTLP push (``--force``, ``--compress``, ``--endpoint``, ``--allow-insecure``)
are refused rather than ignored.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from opentine._cli_common import BRAND, _find_run, _terminal, console
from opentine._cli_flags import refuse_unhonoured
from opentine._cli_json import emit


def export_entire(args: argparse.Namespace) -> None:
    from opentine._entire_export import write_checkpoint
    from opentine._graph_serde import run_from_dict, run_to_dict
    from opentine.core import Run

    refuse_unhonoured(
        args,
        ("force", "compress", "endpoint", "allow_insecure"),
        mode="with --format entire",
        hint="The checkpoint is a ref in the --output git repository.",
    )
    if not args.output:
        console.print("[red]--format entire needs --output REPO: the git repository to write.[/]")
        raise SystemExit(1)
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {_terminal(args.run_id)}[/]")
        raise SystemExit(1)
    repo = Path(args.output)
    try:
        raw = Run.load(path)
        run = run_from_dict(run_to_dict(raw, redact=True), type(raw))
        written = write_checkpoint(repo, run)
    except (OSError, RecursionError, TypeError, ValueError, RuntimeError) as exc:
        console.print(f"[red]Export failed:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    if getattr(args, "json", False):
        emit({"command": "export", "format": "entire", "run_id": run.id, **written})
        return
    console.print(
        f"[{BRAND}]# Exported[/] {_terminal(run.id)} [{BRAND}]as Entire checkpoint[/] "
        f"{written['checkpoint_id']} -> {_terminal(repo)} {written['ref']}"
    )


__all__ = ["export_entire"]
