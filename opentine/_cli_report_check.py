"""``tine verify-report check|data|attach PATH``: a verify report as evidence (X22).

``check`` verifies a ``tine-verify-report/2`` written with ``--sign-key``
offline: its ``tine-sig/3`` signature (against ``--pubkey``, else the embedded
key, reported as trust on first use) and every RFC 3161 token over that
signature (against ``--tsa-roots`` / ``--trusted-root``), and prints the
verified signing time. It exits 0 when the report is authentic, whatever the
verdict *inside* it, and 4 when the signature or a token fails. A ``/1`` report
or an unsigned ``/2`` is read and summarised but exits 4 (not evidence) unless
``--allow-unsigned``. ``data`` prints the ``sig:sha256:`` bytes a TSA query
must cover; ``attach`` stores the response in the report.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import VERIFICATION_FAILED, fail

MAX_TOKEN = 256 * 1024


def add_report_check_parser(sub: Any) -> None:
    group = sub.add_parser("verify-report", help="Check a signed verify report offline")
    actions = group.add_subparsers(dest="report_command", required=True)
    check = actions.add_parser("check", help="Verify a report's signature and timestamps")
    check.add_argument("path", metavar="PATH")
    check.add_argument("--pubkey", help="Trusted Ed25519 public key of the report's signer")
    check.add_argument("--tsa-roots", metavar="FILE.pem", help="Trusted TSA roots")
    check.add_argument("--trusted-root", metavar="FILE", help="Sigstore trusted_root.json")
    check.add_argument(
        "--allow-unsigned", action="store_true", help="Exit 0 for a /1 or unsigned report"
    )
    check.add_argument("--json", action="store_true", help="Emit a JSON object instead")
    data = actions.add_parser("data", help="Print the bytes a token over the report must cover")
    data.add_argument("path", metavar="PATH")
    attach = actions.add_parser("attach", help="Store a TSA response in the report")
    attach.add_argument("path", metavar="PATH")
    attach.add_argument("token", metavar="TOKEN.tsr", help="DER TimeStampResp or token")


def _load(path: str) -> dict[str, Any]:
    from opentine import _verify_report_sign as signed

    try:
        return signed.load(path)
    except (OSError, ValueError) as exc:
        fail(f"cannot read report: {exc}", cause=exc)


def cmd_verify_report(args: argparse.Namespace) -> None:
    from opentine import _verify_report_sign as signed

    doc = _load(args.path)
    if args.report_command == "data":
        try:
            sys.stdout.write(signed.bound(doc))
        except ValueError as exc:
            fail(str(exc), cause=exc)
        sys.stdout.flush()
        return
    if args.report_command == "attach":
        _attach(args, doc)
        return
    public_key = None
    if args.pubkey:
        from opentine._signing_keys import SignatureError, ed25519_public_from_file

        try:
            public_key = ed25519_public_from_file(args.pubkey)
        except (OSError, SignatureError, ValueError) as exc:
            fail(f"cannot read --pubkey: {exc}", cause=exc)
    try:
        result = signed.check(doc, args, public_key)
    except (OSError, ValueError) as exc:
        fail(f"cannot check report: {exc}", cause=exc)
    passed = result["ok"] or (args.allow_unsigned and not result["signed"])
    if args.json:
        print(json.dumps({**result, "command": "verify-report check"}, sort_keys=True))
    else:
        _render(args.path, result)
    if not passed:
        raise SystemExit(VERIFICATION_FAILED)


def _render(path: str, result: dict[str, Any]) -> None:
    head = f"{_terminal(path)}: {result['schema']}, report verdict {result['report_verdict']}"
    console.print(head)
    sig = result["signature"]
    if sig is None:
        console.print("[yellow]unsigned: a readable report, not evidence[/]")
        return
    style = "green" if sig["ok"] else "red"
    console.print(f"  [{style}]signature {sig['state']}[/]: {_terminal(sig['reason'])}")
    console.print(f"  trust basis: {_terminal(sig['trust_basis'])}")
    for stamp in result["timestamps"]:
        console.print(f"  timestamp {stamp['outcome']}: {stamp['reason']}")
    if result["signing_time"]:
        console.print(f"  verified signing time: {result['signing_time']}")
    console.print("[green]REPORT AUTHENTIC[/]" if result["ok"] else "[red]REPORT NOT VERIFIED[/]")


def _attach(args: argparse.Namespace, doc: dict[str, Any]) -> None:
    from opentine import _verify_report_sign as signed
    from opentine._export_write import write_private

    try:
        with open(args.token, "rb") as handle:
            raw = handle.read(MAX_TOKEN + 1)
        if len(raw) > MAX_TOKEN:
            raise ValueError(f"{args.token} exceeds {MAX_TOKEN} bytes")
        updated = signed.attach(doc, raw)
        write_private(Path(args.path), signed.dumps(updated))
    except (OSError, ValueError) as exc:
        fail(f"cannot attach the token: {exc}", cause=exc)
    console.print(f"[green]attached[/] timestamp -> {_terminal(args.path)}")


COMMANDS = {"verify-report": cmd_verify_report}

__all__ = ["COMMANDS", "add_report_check_parser", "cmd_verify_report"]
