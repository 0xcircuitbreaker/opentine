"""``tine redact check|verify|rules``, ``tine purge`` and ``tine doctor`` (0.45, 0.46).

The ``redact`` verbs live in :mod:`opentine._cli_redact`, ``purge`` in
:mod:`opentine._cli_purge`. ``tine doctor`` prints
offline environment checks (:mod:`opentine._doctor`); ``--bundle PATH`` also
writes them as a redacted support bundle. ``--json`` output follows
``tine-cli-doctor-1``; the command exits 1 only on a ``fail`` row.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from rich.markup import escape

from opentine._cli_common import console
from opentine._cli_project import add_project_parser, cmd_project
from opentine._cli_purge import add_purge_parser, cmd_purge
from opentine._cli_redact import add_redact_parser, cmd_redact


def add_hygiene_parsers(sub: Any) -> None:
    add_redact_parser(sub)
    add_purge_parser(sub)  # 0.46: tine purge, tombstones
    add_project_parser(sub)  # 0.46.1: tine project, opentine.project manifests
    doctor = sub.add_parser("doctor", help="Check environment, keys, hooks, harnesses, remotes")
    doctor.add_argument("--repo", default=".")
    doctor.add_argument("--bundle", metavar="PATH", help="Write a redacted support bundle")
    doctor.add_argument("--json", action="store_true")


def cmd_doctor(args: argparse.Namespace) -> None:
    from opentine import _doctor
    from opentine._cli_json import emit
    from opentine._codec_io import atomic_write_bytes

    body = _doctor.report(args.repo)
    if args.bundle:
        atomic_write_bytes(Path(args.bundle), _doctor.bundle(body))
    if args.json:
        emit({"command": "doctor", **body})
    else:
        colors = {"ok": "green", "warn": "yellow", "fail": "red"}
        for row in body["checks"]:
            color = colors[row["status"]]
            console.print(
                f"[{color}]{row['status']:>4}[/]  {row['check']:<11} {escape(row['detail'])}"
            )
        if args.bundle:
            console.print(f"support bundle written: {args.bundle}")
    if body["status"] == "fail":
        raise SystemExit(1)


COMMANDS = {"redact": cmd_redact, "purge": cmd_purge, "doctor": cmd_doctor, "project": cmd_project}

__all__ = ["COMMANDS", "add_hygiene_parsers", "cmd_doctor", "cmd_purge", "cmd_redact"]
