"""``tine gc``/``repack`` opt-ins for local pack forms: blob deltas and dictionaries."""

from __future__ import annotations

import argparse


def add_pack_form_flags(command: argparse.ArgumentParser) -> None:
    deltas = command.add_mutually_exclusive_group()
    deltas.add_argument(
        "--blob-deltas", action="store_true", help="Opt in to blob delta packs (storage "
        "v3; opentine 0.39 and older then refuse the repository until --no-blob-deltas)",
    )  # fmt: skip
    deltas.add_argument("--no-blob-deltas", action="store_true", help="Rewrite packs whole")
    dicts = command.add_mutually_exclusive_group()
    dicts.add_argument(
        "--dictionaries", action="store_true", help="Opt in to per-kind zstd dictionaries "
        "in local packs (storage v3; opentine 0.49 and older then refuse the repository "
        "until --no-dictionaries)",
    )  # fmt: skip
    dicts.add_argument(
        "--no-dictionaries", action="store_true", help="Rewrite packs without dictionaries"
    )


def opt_in(repo, args: argparse.Namespace) -> bool:
    """Descriptor changes before gc; ``True`` when gc must rewrite every pack in v3."""
    from opentine.repository import _gc_deltas, _gc_dicts

    if getattr(args, "blob_deltas", False):
        _gc_deltas.enable(repo)  # descriptor first; the repack below writes the deltas
    if getattr(args, "dictionaries", False):
        _gc_dicts.enable(repo)
    return bool(getattr(args, "blob_deltas", False) or getattr(args, "dictionaries", False))


def opt_out(repo, args: argparse.Namespace) -> None:
    """After gc: rewrite packs without the forms the user turned off."""
    from opentine.repository import _gc_deltas, _gc_dicts

    if getattr(args, "no_blob_deltas", False):
        _gc_deltas.disable(repo)
    if getattr(args, "no_dictionaries", False):
        _gc_dicts.disable(repo)
