"""``tine migrate --to v4 FILE [-o OUT] [--in-place]`` and ``--repo PATH RUN``.

The default writes ``NAME.v4.tine`` next to the original and never touches it.
``--in-place`` is explicit, keeps ``NAME.tine.v2.bak``, and warns that whatever
referred to the original's bytes (signatures, attestations, evidence
manifests) no longer matches. ``upgraded_from`` (SPEC 9.9) is built from the
source's own bytes and the verdict ``verify_artifact`` gives at upgrade time.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Any, NoReturn

from opentine._canon import FORMAT_VERSION
from opentine._cli_errors import fail
from opentine._cli_flags import refuse_conflict, refuse_unhonoured

V4 = 4
V4_ONLY = ("output", "source_repo", "pubkey", "pin")
_READ_ERRORS = (OSError, KeyError, RecursionError, UnicodeDecodeError, ValueError)


def migrate_target(text: str) -> int:
    """``--to``: an integer version, optionally spelled ``vN``."""
    try:
        return int(str(text).strip().lower().removeprefix("v"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a format version: {text!r}") from exc


def add_migrate_parser(sub: Any) -> None:
    migrate = sub.add_parser("migrate", help="Upgrade a .tine file to format v4 (the default)")
    migrate.add_argument("run_id")
    migrate.add_argument(
        "--to",
        type=migrate_target,
        default=None,
        help=f"Target version: v4 (default) or {FORMAT_VERSION} (deprecated)",
    )
    migrate.add_argument("--dry-run", action="store_true")
    migrate.add_argument("--in-place", action="store_true")
    migrate.add_argument("--save")
    migrate.add_argument("--force", action="store_true")
    migrate.add_argument("-o", "--output", help="--to v4: the file to write (default NAME.v4.tine)")
    migrate.add_argument(
        "--repo", dest="source_repo", metavar="PATH", help="--to v4: upgrade RUN from a v3 repo"
    )
    migrate.add_argument("--pubkey", help="--to v4: trusted Ed25519 key for the source signature")
    migrate.add_argument(
        "--pin", action="append", metavar="FINGERPRINT", help="--to v4: pin the source's key"
    )


def refuse_v4_only(args: argparse.Namespace) -> None:
    refuse_unhonoured(
        args, V4_ONLY, mode="without --to v4", hint="They build a format v4 file; add --to v4."
    )


def _refuse_conflicts(args: argparse.Namespace) -> None:
    if args.dry_run:
        refuse_unhonoured(
            args,
            ("in_place", "output", "save"),
            mode="with --dry-run",
            hint="A dry run only reports what a migration would change; drop --dry-run to write.",
        )
    refuse_unhonoured(
        args, ("save",), mode="with --to v4", hint="Name the v4 file with -o/--output."
    )
    refuse_conflict(
        args, ("in_place", "output"), hint="--in-place rewrites the source; -o writes a new file."
    )
    if args.source_repo:
        refuse_unhonoured(
            args,
            ("in_place", "pubkey", "pin"),
            mode="with --repo",
            hint="A repository run is never rewritten and carries no file signature.",
        )


def _fail(message: str, exc: BaseException | None = None) -> NoReturn:
    fail(message, cause=exc)


def _from_repo(args: argparse.Namespace) -> tuple[bytes, Path]:
    """The run's stored envelopes, verbatim: the v4 root *is* the repository oid.

    No ``upgraded_from`` is added (it would change the root); the root itself
    names the repository run it came from (SPEC 9.10).
    """
    from opentine._artifact_v4_repo import export_v4
    from opentine._cli_common import _terminal
    from opentine.repository import Repo

    try:
        repo = Repo.open(args.source_repo)
        oid = args.run_id if args.run_id.startswith("run:") else repo.read_ref(args.run_id)
        if not oid:
            raise KeyError(args.run_id)
        encoded = export_v4(repo, oid)
    except _READ_ERRORS as exc:
        _fail(f"Cannot read {_terminal(args.run_id)} from the repository: {_terminal(exc)}", exc)
    return encoded, Path(f"{oid.rsplit(':', 1)[-1][:12]}.v4.tine")


def _from_file(args: argparse.Namespace, path: Path) -> tuple[Any, dict[str, Any], Path] | None:
    from opentine._cli_common import _terminal
    from opentine._format_v4 import ARTIFACT_V4_KIND, is_v4_artifact
    from opentine._graph_serde import load_run_data
    from opentine._provenance_source import read_source, upgrade_record
    from opentine.core import Run
    from opentine.migrations import is_legacy_linear

    try:
        digest, data = read_source(path)
    except _READ_ERRORS as exc:
        _fail(f"Cannot read {_terminal(path)}: {_terminal(exc)}", exc)
    if is_v4_artifact(data):
        from opentine._cli_common import console

        console.print(f"{_terminal(path)} is already format v4 ({ARTIFACT_V4_KIND}).")
        return None
    if not is_legacy_linear(data):
        result = Run.verify_integrity(data)
        if not result.ok and not args.force:
            _fail(f"Refusing to migrate: {_terminal(result.reason)}. Pass --force.")
    try:
        run = load_run_data(data, Run)
    except _READ_ERRORS as exc:
        _fail(f"Migration failed: {_terminal(exc)}", exc)
    record = upgrade_record(args, path, digest, data)
    name = path.name.removesuffix(".tine")
    return run, record, path.with_name(f"{name}.v4.tine")


def cmd_migrate_v4(args: argparse.Namespace) -> None:
    from opentine._artifact_v4 import write_v4
    from opentine._cli_common import BRAND, _find_run, _terminal, console
    from opentine._codec_io import write_artifact

    _refuse_conflicts(args)
    path = None
    if args.source_repo:
        encoded, output = _from_repo(args)
        state = "not-applicable"
    else:
        path = _find_run(args.run_id)
        if not path:
            _fail(f"Run not found: {_terminal(args.run_id)}")
        loaded = _from_file(args, Path(path))
        if loaded is None:
            return
        run, record, output = loaded
        run._v4_upgraded_from = record
        state = record["signature"]["state"]
        try:
            encoded = write_v4(run)
        except ValueError as exc:  # a wide integer, a size bound: never rounded or repaired
            _fail(f"Migration to v4 failed: {_terminal(exc)}", exc)
    from opentine._artifact_v4_read import read_v4

    root = read_v4(encoded)._v4_origin["root"]
    output = Path(path) if args.in_place else Path(args.output) if args.output else output
    if args.dry_run:
        console.print(f"[{BRAND}]# Migration preview[/] -> format v4 {_terminal(output)}")
        console.print(f"  root: {root}\n  source signature at upgrade: {state}")
        return
    if args.in_place:
        backup = Path(path).with_name(Path(path).name + ".v2.bak")
        if backup.exists() and not args.force:
            _fail(f"Refusing to overwrite existing backup: {_terminal(backup)}. Pass --force.")
        shutil.copy2(path, backup)
    elif output.exists() and not args.force:
        _fail(f"Refusing to overwrite existing file: {_terminal(output)}. Pass --force.")
    write_artifact(output, encoded.decode("utf-8"))
    console.print(f"[{BRAND}]# Migrated[/] {_terminal(args.run_id)} -> format v4 root {root}")
    console.print(f"[dim]Saved:[/] {_terminal(output)} (source signature at upgrade: {state})")
    if args.in_place:
        console.print(
            f"[yellow]Backup: {_terminal(backup)}. Signatures, attestations and evidence "
            "manifests made over the original's bytes are now orphaned: re-sign the v4 file.[/]"
        )


__all__ = ["add_migrate_parser", "cmd_migrate_v4", "migrate_target", "refuse_v4_only"]
