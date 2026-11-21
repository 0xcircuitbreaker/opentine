"""``tine bom export VARIANT --format cyclonedx|spdx [--out FILE]`` (0.78): AI-BOM export.

Exports one lineage node (0.58) as a CycloneDX 1.6 ML-BOM or an SPDX 3.0.1
AI/Dataset profile document (:mod:`opentine._aibom`, docs/AIBOM.md). The node
must pass ``tine lineage check`` (with the 0.60/0.61 taint findings): a node
that does not is refused and nothing is written. Output is deterministic: the
same folder, dataset versions and options give the same bytes. Without
``--out`` the document is written to stdout as bytes; ``--json`` (with
``--out``) prints a ``tine-cli-bom/1`` summary instead.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from collections.abc import Callable
from pathlib import Path

from opentine._cli_errors import USAGE, error
from opentine._lineage import MAX_BYTES, MAX_FILES

SCHEMA = "tine-cli-bom/1"
FORMATS = ("cyclonedx", "spdx")


def add_bom_parser(subparsers: argparse._SubParsersAction) -> None:
    bom = subparsers.add_parser("bom", help="AI-BOM export of a lineage node")
    verbs = bom.add_subparsers(dest="bom_command", required=True)
    export = verbs.add_parser("export", help="CycloneDX 1.6 ML-BOM or SPDX 3.0.1 AI document")
    export.add_argument("variant", metavar="LINEAGE_NODE", help="The variant id (sha256:HEX)")
    export.add_argument("--format", choices=FORMATS, required=True, help="Document format")
    export.add_argument("--out", metavar="FILE", help="Write here (default: stdout)")
    export.add_argument("--repo", default=".", metavar="PATH", help="v3 repository")
    export.add_argument("--dir", metavar="DIR", help="Lineage folder (REPO/.tine/lineage)")
    export.add_argument("--dataset", action="append", default=[], metavar="ROLE=FILE",
                        help="A signed dataset version (training|eval); repeatable")  # fmt: skip
    export.add_argument("--licence", "--license", dest="licence", metavar="EXPR",
                        help="The model's SPDX licence expression")  # fmt: skip
    export.add_argument("--name", metavar="NAME", help="The model's name in the document")
    export.add_argument("--promotion-policy", metavar="TOML",
                        help="Also pin eval signers to this policy's eval_signers")  # fmt: skip
    export.add_argument("--max-files", type=int, default=MAX_FILES, metavar="N",
                        help=f"Refuse a lineage folder over N files ({MAX_FILES})")  # fmt: skip
    export.add_argument("--max-bytes", type=int, default=MAX_BYTES, metavar="N",
                        help=f"Refuse a lineage folder over N bytes ({MAX_BYTES})")  # fmt: skip
    export.add_argument("--json", action="store_true", help="Print a summary (needs --out)")


def build(args: argparse.Namespace) -> bytes:
    """The document's bytes for *args* (raises ``BomError``/``ValueError`` on refusal)."""
    from opentine import _aibom_cdx, _aibom_spdx
    from opentine._aibom import BomError, collect, curators, read_dataset, render
    from opentine._cli_lineage import _folder, tainted, trust
    from opentine._lineage_check import check, read_folder

    if args.name is not None and not (args.name.strip() and args.name.isprintable()
                                      and len(args.name) <= 256):  # fmt: skip
        raise BomError("--name is 1..256 printable characters")
    counting = curators(Path(args.repo)) if args.dataset else set()
    datasets = [read_dataset(spec, counting) for spec in args.dataset]
    files = read_folder(_folder(args), max_files=args.max_files, max_bytes=args.max_bytes)
    row = tainted(args, files, check(files, args.variant, trust(args)))
    model = collect(files, row, name=args.name, licence=args.licence, datasets=datasets)
    render_doc = _aibom_cdx.document if args.format == "cyclonedx" else _aibom_spdx.document
    return render(render_doc(model))


def cmd_bom(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine._key_store import PassphraseUnavailable

    if args.json and not args.out:
        raise error("--json prints a summary; pass --out FILE for the document", USAGE,
                    prefix="bom: ")  # fmt: skip
    try:
        data = build(args)
    except (PassphraseUnavailable, OSError, ValueError, KeyError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
        raise error(message, prefix="bom: ") from exc
    if args.out:
        from opentine._canon import atomic_write_text

        atomic_write_text(args.out, data.decode("utf-8"), newline="\n")
    else:
        sys.stdout.flush()
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    if args.json:
        emit({"command": "bom export", "schema": SCHEMA, "ok": True, "format": args.format,
              "variant": args.variant, "out": Path(args.out).as_posix(),
              "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})  # fmt: skip


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"bom": cmd_bom}

__all__ = ["COMMANDS", "FORMATS", "SCHEMA", "add_bom_parser", "build", "cmd_bom"]
