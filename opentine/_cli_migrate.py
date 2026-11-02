"""Legacy in-file migration command."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from opentine._artifact_io import read_artifact_json
from opentine._canon import FORMAT_VERSION, _integrity_digest
from opentine._cli_common import BRAND, _find_run, _terminal, console
from opentine._cli_flags import refuse_conflict, refuse_unhonoured
from opentine._cli_migrate_v4 import V4, cmd_migrate_v4, refuse_v4_only
from opentine._format_v4 import ARTIFACT_V4_KIND, is_v4_artifact, v4_requested, write_format
from opentine.core import Run
from opentine.migrations import is_legacy_linear


def _refuse_ignored_migrate_flags(args: argparse.Namespace) -> None:
    """Refuse destination flags the preview would print over and drop."""
    if args.dry_run:
        # The preview returns before any write, so --save/--in-place were accepted
        # and then discarded: the command exited 0 having written nothing.
        refuse_unhonoured(
            args,
            ("in_place", "save"),
            mode="with --dry-run",
            hint="A dry run only reports what a migration would change; drop --dry-run to write.",
        )
    refuse_conflict(
        args,
        ("in_place", "save"),
        hint="--in-place rewrites the source; --save writes a new file.",
    )


def cmd_migrate(args: argparse.Namespace) -> None:
    if args.to is None:  # 0.26: v4 unless a deprecated legacy writer is chosen
        args.to = V4 if v4_requested() else FORMAT_VERSION
        if args.to == V4 and args.save and not args.dry_run and not args.output:
            args.output, args.save = args.save, None  # the pre-0.26 spelling of -o
    if args.to == V4:
        return cmd_migrate_v4(args)
    refuse_v4_only(args)
    _refuse_ignored_migrate_flags(args)
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {_terminal(args.run_id)}[/]")
        raise SystemExit(1)
    try:
        raw = read_artifact_json(path)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        console.print(f"[red]Cannot read {_terminal(path)}: {_terminal(exc)}[/]")
        raise SystemExit(1) from exc
    if is_v4_artifact(raw):
        console.print(
            f"{_terminal(path)} is already format v4 ({ARTIFACT_V4_KIND}); nothing to migrate. "
            "v4 is never rewritten as v2."
        )
        return
    legacy = is_legacy_linear(raw)
    source_version = "0 (legacy 0.1.0)" if legacy else raw.get("format_version", "missing")
    target = args.to if args.to is not None else FORMAT_VERSION
    if target != FORMAT_VERSION:
        console.print(f"[red]This build migrates to format v{FORMAT_VERSION} or v4.[/]")
        raise SystemExit(1)
    if not legacy:
        source_result = Run.verify_integrity(path)
        if not source_result.ok and not args.force:
            console.print(
                f"[red]Refusing to migrate: {_terminal(source_result.reason)}. Pass --force.[/]"
            )
            raise SystemExit(1)
    try:
        run = Run.load(path)
    except ValueError as exc:
        console.print(f"[red]Migration failed:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    if source_version == run.format_version:
        console.print(f"[dim]{_terminal(path.name)} is already at format v{run.format_version}.[/]")
        # --in-place is satisfied (the source already is at this version), but a
        # --save destination is not: exiting 0 would tell a script that path exists.
        if args.save:
            console.print(f"[red]Nothing to migrate; {_terminal(args.save)} was not written.[/]")
            raise SystemExit(1)
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
        console.print(f"[{BRAND}]# Migration preview[/] {_terminal(path.name)}")
        # Both come from the artifact, which may be hostile: escaped like any run text.
        console.print(f"  format_version: {_terminal(source_version)} -> {run.format_version}")
        old_digest = _terminal(str(old_integrity.get("digest", ""))[:12]) or "-"
        console.print(f"  digest: {old_digest} -> {new_digest[:12]}")
        if signature_dropped:
            console.print("  [yellow]signature dropped — re-sign after migrating[/]")
        return
    output = path if args.in_place else Path(args.save)
    if not args.in_place and output.exists() and not args.force:
        console.print(
            f"[red]Refusing to overwrite existing file: {_terminal(output)}. Pass --force.[/]"
        )
        raise SystemExit(1)
    with write_format(FORMAT_VERSION):  # --to 2 is the deprecated legacy writer
        run.save(output)
    badge = "[green]OK[/]" if Run.verify_integrity(output).ok else "[red]FAILED[/]"
    console.print(
        f"[{BRAND}]# Migrated[/] {_terminal(path.name)} v{_terminal(source_version)} "
        f"-> v{run.format_version}"
    )
    console.print(f"[dim]Saved:[/] {_terminal(output)} {badge}")
