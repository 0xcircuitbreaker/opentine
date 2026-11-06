"""``tine archive create|restore``: a whole repository in one compressed file."""

from __future__ import annotations

import argparse

from opentine._cli_common import BRAND, _terminal, console


def add_archive_parsers(sub: argparse._SubParsersAction, codecs: tuple[str, ...]) -> None:
    archive = sub.add_parser("archive", help="Write or restore a whole-repository archive")
    actions = archive.add_subparsers(dest="archive_action", required=True)
    create = actions.add_parser("create", help="Archive a repository into one compressed file")
    create.add_argument("output")
    create.add_argument("--repo", default=".")
    form = create.add_mutually_exclusive_group()
    form.add_argument("--codec", choices=codecs)
    form.add_argument(
        "--archival",
        action="store_true",
        help="Write xz (or zlib), so Python 3.11+ restores it with the stdlib alone; "
        "opentine 0.36 and older cannot read an xz archive",
    )
    restore = actions.add_parser("restore", help="Restore an archive into a new repository")
    restore.add_argument("archive")
    restore.add_argument("destination")


def cmd_archive(args: argparse.Namespace) -> None:
    try:
        _archive(args)
    except (OSError, ValueError) as exc:
        _storage()._refuse(exc)


def _archive(args: argparse.Namespace) -> None:
    from opentine.repository._archive import create_archive, restore_archive

    if args.archive_action == "create":
        stats = create_archive(_storage()._repo(args.repo), args.output, codec=_archive_codec(args))
        console.print(
            f"[{BRAND}]# Archived[/] {stats['objects']} object(s): "
            f"{_storage()._size(stats['raw_bytes'])} → {_storage()._size(stats['archive_bytes'])} "
            f"[{BRAND}]in[/] {_terminal(args.output)}"
        )
        return
    stats = restore_archive(args.archive, args.destination)
    console.print(
        f"[{BRAND}]# Restored[/] {stats['objects']} object(s) and {stats['refs']} ref(s) "
        f"[{BRAND}]into[/] {_terminal(stats['path'])}"
    )


def _archive_codec(args: argparse.Namespace) -> str | None:
    from opentine._codec import archival_codec

    return archival_codec() if args.archival else args.codec


def _storage():
    from opentine import _cli_storage

    return _cli_storage
