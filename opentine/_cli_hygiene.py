"""``tine redact check|verify|rules``, ``tine purge`` and ``tine doctor`` (0.45, 0.46).

The ``redact`` verbs live in :mod:`opentine._cli_redact`, ``purge`` in
:mod:`opentine._cli_purge`; ``tine merge``, ``pick`` and ``merge-queue`` (0.47)
in :mod:`opentine._cli_merge`; ``tine code-graph`` (0.48) in :mod:`opentine._cli_graph`.
``tine doctor`` prints offline environment checks
(:mod:`opentine._doctor`); ``--bundle PATH`` also
writes them as a redacted support bundle. ``--json`` output follows
``tine-cli-doctor-1``; the command exits 1 only on a ``fail`` row.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from rich.markup import escape

from opentine._cli_alert import add_alert_parser, cmd_alert
from opentine._cli_audit_kit import add_audit_kit_parser, cmd_audit_kit
from opentine._cli_common import console
from opentine._cli_compliance import add_compliance_parser, cmd_compliance
from opentine._cli_extend import COMMANDS as EXTEND_COMMANDS
from opentine._cli_extend import add_extend_parsers
from opentine._cli_forge import add_forge_parser, cmd_forge
from opentine._cli_graph import add_graph_parser, cmd_graph
from opentine._cli_memory import add_memory_parser, cmd_memory
from opentine._cli_merge import COMMANDS as MERGE_COMMANDS
from opentine._cli_merge import add_merge_parsers
from opentine._cli_project import add_project_parser, cmd_project
from opentine._cli_prompt import add_prompt_parser, cmd_prompt
from opentine._cli_publish import add_publish_parser, cmd_publish
from opentine._cli_purge import add_purge_parser, cmd_purge
from opentine._cli_redact import add_redact_parser, cmd_redact
from opentine._cli_review import add_review_parser, cmd_review


def add_hygiene_parsers(sub: Any) -> None:
    add_redact_parser(sub)
    add_purge_parser(sub)  # 0.46: tine purge, tombstones
    add_project_parser(sub)  # 0.46.1: tine project, opentine.project manifests
    add_merge_parsers(sub)  # 0.47: tine merge, tine pick, tine merge-queue
    add_review_parser(sub)  # 0.47: tine review, opentine.review and its gate decisions
    add_prompt_parser(sub)  # 0.47: tine prompt, opentine.prompt versions
    add_memory_parser(sub)  # 0.47: tine memory, opentine.memory notes
    add_extend_parsers(sub)  # 0.47: tine plugins, tine experts
    add_forge_parser(sub)  # 0.48: tine forge publish, opentine.forge-check
    add_publish_parser(sub)  # 0.49: tine publish zenodo | hf
    add_graph_parser(sub)  # 0.48: tine code-graph, the code map
    add_compliance_parser(sub)  # 0.48: tine compliance list|check
    add_audit_kit_parser(sub)  # 0.49: tine audit-kit build|verify
    add_alert_parser(sub)  # 0.49: tine alert add|list|remove|test
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


COMMANDS = {
    "redact": cmd_redact,
    "purge": cmd_purge,
    "doctor": cmd_doctor,
    "project": cmd_project,
    **MERGE_COMMANDS,
}
COMMANDS["review"] = cmd_review  # 0.47
COMMANDS["prompt"] = cmd_prompt  # 0.47
COMMANDS["memory"] = cmd_memory  # 0.47
COMMANDS.update(EXTEND_COMMANDS)  # 0.47
COMMANDS["forge"] = cmd_forge  # 0.48
COMMANDS["publish"] = cmd_publish  # 0.49
COMMANDS["code-graph"] = cmd_graph  # 0.48
COMMANDS["compliance"] = cmd_compliance  # 0.48
COMMANDS["audit-kit"] = cmd_audit_kit  # 0.49
COMMANDS["alert"] = cmd_alert  # 0.49

__all__ = ["COMMANDS", "add_hygiene_parsers", "cmd_doctor", "cmd_purge", "cmd_redact"]
