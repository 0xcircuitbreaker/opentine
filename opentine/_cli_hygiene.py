"""``tine redact check`` and ``tine doctor [--bundle PATH]`` (0.45).

``tine redact check`` re-scans every run reachable from the repository's
``heads/*`` refs (or the ``--run`` given) with the current redaction ruleset and
prints one redaction report per run (:mod:`opentine._push_gate`); a key flag
signs each report. It exits 1 when any run has findings -- the same objects the
pre-push gate would refuse.

``tine doctor`` prints offline environment checks (:mod:`opentine._doctor`);
``--bundle PATH`` also writes them as a redacted support bundle.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rich.markup import escape

from opentine._cli_common import console


def add_hygiene_parsers(sub: Any) -> None:
    redact = sub.add_parser("redact", help="Re-scan stored runs with the current redaction rules")
    actions = redact.add_subparsers(dest="redact_command", required=True)
    check = actions.add_parser("check", help="One redaction report per run; exit 1 on findings")
    check.add_argument("--repo", default=".")
    check.add_argument("--run", action="append", metavar="RUN", help="Run oid or ref (repeatable)")
    keys = check.add_mutually_exclusive_group()
    keys.add_argument("--key-file", metavar="PATH", help="Sign each report (HMAC key file)")
    keys.add_argument("--ed25519-key-file", metavar="PATH", help="Sign each report (Ed25519)")
    check.add_argument("--key-id", help="Key id recorded in each report signature")
    check.add_argument("--out", metavar="PATH", help="Also write the reports as JSON to PATH")
    check.add_argument("--json", action="store_true")
    doctor = sub.add_parser("doctor", help="Check environment, keys, hooks, harnesses, remotes")
    doctor.add_argument("--repo", default=".")
    doctor.add_argument("--bundle", metavar="PATH", help="Write a redacted support bundle")
    doctor.add_argument("--json", action="store_true")


def _runs(repo: Any, wanted: list[str] | None) -> list[str]:
    if wanted:
        out = []
        for name in wanted:
            oid = name if repo.has(name) else repo.read_ref(name)
            if not oid:
                raise ValueError(f"run not found: {name}")
            out.append(oid)
        return out
    heads = [repo.read_ref(n) for n in sorted(repo.list_refs()) if n.startswith("heads/")]
    return sorted({oid for oid in heads if oid and oid.startswith("run:")})


def _signer(args: argparse.Namespace):
    from opentine import _push_gate
    from opentine._signing_keys import ed25519_private_from_file, hmac_key_from_file

    if args.key_id and not (args.key_file or args.ed25519_key_file):
        raise ValueError("--key-id needs --key-file or --ed25519-key-file")
    if args.key_file:
        key, algorithm = hmac_key_from_file(args.key_file), "hmac-sha256"
    elif args.ed25519_key_file:
        key, algorithm = ed25519_private_from_file(args.ed25519_key_file), "ed25519"
    else:
        return lambda body: body
    return lambda body: _push_gate.sign(body, key, algorithm=algorithm, key_id=args.key_id)


def cmd_redact(args: argparse.Namespace) -> None:
    from opentine import _push_gate
    from opentine._codec_io import atomic_write_bytes
    from opentine.kernel import canonical_json
    from opentine.repository import Repo

    repo = Repo.open(args.repo)
    sign = _signer(args)
    reports = [sign(_push_gate.run_report(repo, oid)) for oid in _runs(repo, args.run)]
    clean = all(report["clean"] for report in reports)
    if args.out:
        atomic_write_bytes(Path(args.out), canonical_json(reports))
    if args.json:
        print(json.dumps({"clean": clean, "reports": reports}, indent=2))
    else:
        for report in reports:
            mark = "[green]clean[/]" if report["clean"] else "[red]findings[/]"
            console.print(f"{report['run']}  {mark}  {report['objects']} object(s)")
            for hit in report["findings"]:
                console.print(f"  {hit['kind']}  {hit['oid']}")
    if not clean:
        raise SystemExit(1)


def cmd_doctor(args: argparse.Namespace) -> None:
    from opentine import _doctor
    from opentine._codec_io import atomic_write_bytes

    body = _doctor.report(args.repo)
    if args.bundle:
        atomic_write_bytes(Path(args.bundle), _doctor.bundle(body))
    if args.json:
        print(json.dumps(body, indent=2))
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


COMMANDS = {"redact": cmd_redact, "doctor": cmd_doctor}

__all__ = ["COMMANDS", "add_hygiene_parsers", "cmd_doctor", "cmd_redact"]
