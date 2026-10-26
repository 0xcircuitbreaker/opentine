"""``tine gc``, ``tine repack``, ``tine archive`` and ``tine compress``."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from opentine._cli_common import BRAND, _terminal, console
from opentine._cli_du import DU_COMMANDS

_CODECS = ("zstd", "zlib")


def _size(count: int) -> str:
    value = float(count)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{count} B"


def add_storage_parsers(sub: argparse._SubParsersAction) -> None:
    from opentine._cli_du import add_du_parsers

    add_du_parsers(sub)
    for name, text in (
        ("gc", "Pack loose repository objects into compressed packs"),
        ("repack", "Rewrite every object (loose and packed) into one pack"),
    ):
        command = sub.add_parser(name, help=text)
        command.add_argument("--repo", default=".")
        command.add_argument("--codec", choices=_CODECS, help="Pack codec (default: zstd)")
        command.add_argument(
            "--keep-transfer-packs",
            action="store_true",
            help="Keep the copies of received transfer packs (redundant once packed)",
        )
        command.add_argument("--json", action="store_true")
        change = command.add_mutually_exclusive_group()
        change.add_argument(
            "--upgrade",
            action="store_true",
            help="Opt in to storage version 3 (smaller packs; opentine 0.12 and older "
            "then refuse the repository until --downgrade)",
        )
        change.add_argument(
            "--downgrade",
            action="store_true",
            help="Rewrite every pack for storage version 2, which opentine 0.11-0.12 read",
        )
    archive = sub.add_parser("archive", help="Write or restore a whole-repository archive")
    actions = archive.add_subparsers(dest="archive_action", required=True)
    create = actions.add_parser("create", help="Archive a repository into one compressed file")
    create.add_argument("output")
    create.add_argument("--repo", default=".")
    create.add_argument("--codec", choices=_CODECS)
    restore = actions.add_parser("restore", help="Restore an archive into a new repository")
    restore.add_argument("archive")
    restore.add_argument("destination")
    compress = sub.add_parser(
        "compress", help="Rewrite .tine files compressed (or plain with --decompress)"
    )
    compress.add_argument("paths", nargs="+", help=".tine files, or directories of them")
    compress.add_argument(
        "--decompress",
        action="store_true",
        help="Write plain JSON, which opentine releases before 0.11 can read",
    )


def _repo(path: str):
    from opentine.repository import Repo

    return Repo.open(path)


def _refuse(exc: Exception) -> None:
    console.print(f"[red]{_terminal(exc)}[/]")
    raise SystemExit(1) from exc


def cmd_gc(args: argparse.Namespace) -> None:
    from opentine.repository._gc import gc

    try:
        result = _gc_run(gc, args)
    except (OSError, ValueError) as exc:  # KernelError is a ValueError
        _refuse(exc)
    _report_gc(args, result)


def _gc_run(gc, args: argparse.Namespace):
    return gc(
        _repo(args.repo),
        repack=args.command == "repack",
        codec=args.codec,
        keep_transfer_packs=args.keep_transfer_packs,
        upgrade=args.upgrade,
        downgrade=args.downgrade,
    )


def _report_gc(args: argparse.Namespace, result) -> None:
    if args.json:
        print(json.dumps(result.__dict__, sort_keys=True))
        return
    console.print(
        f"[{BRAND}]# Packed[/] {result.packed} object(s) with {result.codec}: "
        f"{_size(result.bytes_before)} → {_size(result.bytes_after)} "
        f"(on disk {_size(result.disk_before)} → {_size(result.disk_after)})"
    )
    if args.upgrade or args.downgrade:
        version = 3 if args.upgrade else 2
        console.print(f"  repository is now at storage version {version}")
    if result.removed_transfer_packs:
        console.print(f"  removed {result.removed_transfer_packs} received transfer pack copy(ies)")


def cmd_archive(args: argparse.Namespace) -> None:
    try:
        _archive(args)
    except (OSError, ValueError) as exc:
        _refuse(exc)


def _archive(args: argparse.Namespace) -> None:
    from opentine.repository._archive import create_archive, restore_archive

    if args.archive_action == "create":
        stats = create_archive(_repo(args.repo), args.output, codec=args.codec)
        console.print(
            f"[{BRAND}]# Archived[/] {stats['objects']} object(s): "
            f"{_size(stats['raw_bytes'])} → {_size(stats['archive_bytes'])} "
            f"[{BRAND}]in[/] {_terminal(args.output)}"
        )
        return
    stats = restore_archive(args.archive, args.destination)
    console.print(
        f"[{BRAND}]# Restored[/] {stats['objects']} object(s) and {stats['refs']} ref(s) "
        f"[{BRAND}]into[/] {_terminal(stats['path'])}"
    )


def _artifacts(paths: list[str]) -> list[Path]:
    found: list[Path] = []
    for value in paths:
        path = Path(value)
        if path.is_dir():
            found.extend(sorted(p for p in path.rglob("*.tine") if p.is_file()))
        else:
            found.append(path)
    return found


def cmd_compress(args: argparse.Namespace) -> None:
    from opentine._codec_io import recompress

    before = after = changed = 0
    for path in _artifacts(args.paths):
        try:
            old, new = recompress(path, decompress=args.decompress)
        except (OSError, ValueError) as exc:
            console.print(f"[red]{_terminal(path)}: {_terminal(exc)}[/]")
            raise SystemExit(1) from exc
        before, after, changed = before + old, after + new, changed + (old != new)
    verb = "Decompressed" if args.decompress else "Compressed"
    console.print(f"[{BRAND}]# {verb}[/] {changed} file(s): {_size(before)} → {_size(after)}")


STORAGE_COMMANDS = {
    **DU_COMMANDS,
    "archive": cmd_archive,
    "compress": cmd_compress,
    "gc": cmd_gc,
    "repack": cmd_gc,
}
