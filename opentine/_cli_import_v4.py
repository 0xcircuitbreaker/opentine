"""``tine import FILE.tine --repo PATH`` for a format v4 file (SPEC 9.10).

A v4 file is already a bundle of v3 envelopes, so importing it installs them
unchanged: the repository oid is the file's root, the annotation chain is
adopted, and ``tine-sig/3`` blocks go to the signature sidecar. Recognized only
with ``--format auto`` and a regular file whose content is ``tine-artifact/4``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

_MARKS = (b'"tine-artifact/4"', b'"tine-artifact/5"')  # v5 is read as its v4 form


def sniff_v4(source: str) -> dict[str, Any] | None:
    """The parsed v4 document at *source*, or ``None`` when it is not one."""
    from opentine import _codec
    from opentine._artifact_io import MAX_TINE_ARTIFACT_BYTES, parse_artifact_json
    from opentine._format_v4 import is_v4_artifact

    path = Path(source)
    try:
        if not path.is_file() or path.stat().st_size > MAX_TINE_ARTIFACT_BYTES:
            return None
        body = _codec.unwrap(path.read_bytes(), limit=MAX_TINE_ARTIFACT_BYTES)
        if not any(mark in body for mark in _MARKS):
            return None
        data = parse_artifact_json(body)
    except (OSError, RecursionError, UnicodeDecodeError, ValueError):
        return None
    return data if is_v4_artifact(data) else None


def import_v4_file(args: argparse.Namespace) -> bool:
    """Handle a v4 *source*; ``False`` leaves it to the trace importers."""
    from opentine._artifact_v4_repo import install_v4
    from opentine._cli_common import BRAND, _terminal, console
    from opentine.repo import Repo

    if args.format != "auto" or args.from_default_location or args.source in (None, "-"):
        return False
    data = sniff_v4(args.source)
    if data is None:
        return False
    extra = [flag for flag, on in (("--save", args.save), ("--price", args.price)) if on]
    extra += [flag for flag in ("--fleet", "--adapter") if getattr(args, flag[2:], None)]
    if not args.repo or extra:
        console.print(
            "[red]A format v4 file is already a portable run: import it with --repo PATH "
            f"only{' (not ' + ', '.join(extra) + ')' if extra else ''}.[/]"
        )
        raise SystemExit(1)
    try:
        result = install_v4(Repo.open(args.repo), data, ref=args.ref or "heads/main")
    except (KeyError, OSError, RecursionError, ValueError) as exc:
        console.print(f"[red]Import failed:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, sort_keys=True))
        return True
    console.print(
        f"[{BRAND}]# Imported[/] format v4 {_terminal(args.source)} [{BRAND}]as[/] "
        f"{result['root']} ({result['objects_written']} new of {result['objects']} objects, "
        f"annotations {result['annotations']}, {result['signatures']} new signature(s))"
    )
    return True


__all__ = ["import_v4_file", "sniff_v4"]
