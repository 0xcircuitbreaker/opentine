"""Legacy in-file migration command."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.markup import escape

from opentine._artifact_io import read_artifact_json
from opentine._canon import FORMAT_VERSION, _integrity_digest
from opentine._cli_common import BRAND, _find_run, console
from opentine.core import Run
from opentine.migrations import is_legacy_linear


def cmd_migrate(args: argparse.Namespace) -> None:
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {args.run_id}[/]")
        raise SystemExit(1)
    try:
        raw = read_artifact_json(path)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        console.print(f"[red]Cannot read {escape(str(path))}: {escape(str(exc))}[/]")
        raise SystemExit(1) from exc
    legacy = is_legacy_linear(raw)
    source_version = "0 (legacy 0.1.0)" if legacy else raw.get("format_version", "missing")
    target = args.to if args.to is not None else FORMAT_VERSION
    if target != FORMAT_VERSION:
        console.print(f"[red]This build only migrates to format v{FORMAT_VERSION}.[/]")
        raise SystemExit(1)
    if not legacy:
        source_result = Run.verify_integrity(path)
        if not source_result.ok and not args.force:
            console.print(
                f"[red]Refusing to migrate: {escape(source_result.reason)}. Pass --force.[/]"
            )
            raise SystemExit(1)
    try:
        run = Run.load(path)
    except ValueError as exc:
        console.print(f"[red]Migration failed:[/] {escape(str(exc))}")
        raise SystemExit(1) from exc
    if source_version == run.format_version:
        console.print(f"[dim]{path.name} is already at format v{run.format_version}.[/]")
        return
    preview = run.to_dict(redact=True)
    preview["metadata"]["integrity"] = {
        "algorithm": "sha256",
        "digest": _integrity_digest(preview),
    }
    new_digest = preview["metadata"]["integrity"]["digest"]
    old_integrity = (raw.get("metadata") or {}).get("integrity") or {}
    signature_dropped = bool(old_integrity.get("signature"))
    if args.dry_run or (not args.in_place and not args.save):
        console.print(f"[{BRAND}]# Migration preview[/] {escape(path.name)}")
        console.print(f"  format_version: {source_version} -> {run.format_version}")
        old_digest = str(old_integrity.get("digest", ""))[:12] or "-"
        console.print(f"  digest: {old_digest} -> {new_digest[:12]}")
        if signature_dropped:
            console.print("  [yellow]signature dropped — re-sign after migrating[/]")
        return
    output = path if args.in_place else Path(args.save)
    if not args.in_place and output.exists() and not args.force:
        console.print(f"[red]Refusing to overwrite existing file: {output}. Pass --force.[/]")
        raise SystemExit(1)
    run.save(output)
    badge = "[green]OK[/]" if Run.verify_integrity(output).ok else "[red]FAILED[/]"
    console.print(
        f"[{BRAND}]# Migrated[/] {escape(path.name)} v{source_version} -> v{run.format_version}"
    )
    console.print(f"[dim]Saved:[/] {escape(str(output))} {badge}")
