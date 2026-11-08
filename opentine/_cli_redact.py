"""``tine redact check|verify|rules`` (0.45, 0.45.1).

``check`` re-scans every run reachable from ``heads/*`` (or each ``--run``) with
the current ruleset and prints one redaction report per run
(:mod:`opentine._push_gate`); a key flag signs each report. It exits 4
(verification failed) when any run has findings and 3 (not found) for a
``--run`` that does not resolve.

``verify REPORT`` checks the signature and field rules of every report in a
file (one report, the list ``check --out`` writes, or ``check --json`` output):
SPEC 4.13, :mod:`opentine._redact_report`. It exits 4 when any report fails.

``rules`` prints the ruleset as data (``tine-redaction-rules/1``,
:mod:`opentine._redact_rules`).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from opentine._cli_common import console
from opentine._cli_errors import NOT_FOUND, VERIFICATION_FAILED, fail
from opentine._cli_json import emit


def add_redact_parser(sub: Any) -> None:
    redact = sub.add_parser("redact", help="Re-scan, verify and describe redaction")
    actions = redact.add_subparsers(dest="redact_command", required=True)
    check = actions.add_parser("check", help="One redaction report per run; exit 4 on findings")
    check.add_argument("--repo", default=".")
    check.add_argument("--run", action="append", metavar="RUN", help="Run oid or ref (repeatable)")
    keys = check.add_mutually_exclusive_group()
    keys.add_argument("--key-file", metavar="PATH", help="Sign each report (HMAC key file)")
    keys.add_argument("--ed25519-key-file", metavar="PATH", help="Sign each report (Ed25519)")
    check.add_argument("--key-id", help="Key id recorded in each report signature")
    check.add_argument("--out", metavar="PATH", help="Also write the reports as JSON to PATH")
    check.add_argument("--json", action="store_true")
    verify = actions.add_parser("verify", help="Verify signed redaction reports; exit 4 on failure")
    verify.add_argument("report", metavar="REPORT", help="A report file (check --out or --json)")
    trust = verify.add_mutually_exclusive_group()
    trust.add_argument("--key-file", metavar="PATH", help="HMAC key file")
    trust.add_argument("--pubkey", metavar="PATH", help="Trusted Ed25519 public key file")
    verify.add_argument("--json", action="store_true")
    rules = actions.add_parser("rules", help="Print the redaction ruleset as data")
    rules.add_argument("--json", action="store_true")


def _runs(repo: Any, wanted: list[str] | None) -> list[str]:
    if wanted:
        out = []
        for name in wanted:
            try:
                oid = name if repo.has(name) else repo.read_ref(name)
            except ValueError:  # neither an object id nor a valid ref name
                oid = None
            if not oid:
                fail(f"run not found: {name}", NOT_FOUND)
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


def _check(args: argparse.Namespace) -> None:
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
        emit({"command": "redact-check", "clean": clean, "reports": reports})
    else:
        for report in reports:
            mark = "[green]clean[/]" if report["clean"] else "[red]findings[/]"
            console.print(f"{report['run']}  {mark}  {report['objects']} object(s)")
            for hit in report["findings"]:
                console.print(f"  {hit['kind']}  {hit['oid']}")
    if not clean:
        raise SystemExit(VERIFICATION_FAILED)


def _reports(path: str) -> list[Any]:
    try:
        document = json.loads(Path(path).read_bytes().decode("utf-8"))
    except FileNotFoundError:
        fail(f"cannot read {path}: no such file", NOT_FOUND)
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        fail(f"{path} is not a JSON redaction report: {type(exc).__name__}")
    if isinstance(document, dict) and isinstance(document.get("reports"), list):
        return document["reports"]
    return document if isinstance(document, list) else [document]


def _verify(args: argparse.Namespace) -> None:
    from opentine._redact_report import ReportError, check
    from opentine._signing_keys import ed25519_public_from_file, hmac_key_from_file

    hmac = hmac_key_from_file(args.key_file) if args.key_file else None
    public = ed25519_public_from_file(args.pubkey).public_bytes_raw() if args.pubkey else None
    rows: list[dict[str, Any]] = []
    for report in _reports(args.report):
        run = report.get("run") if isinstance(report, dict) else None
        try:
            rows.append({"ok": True, **check(report, hmac_key=hmac, public_key=public)})
        except ReportError as exc:
            rows.append({"ok": False, "run": run if isinstance(run, str) else None,
                         "reason": exc.code, "message": str(exc)})  # fmt: skip
    ok = bool(rows) and all(row["ok"] for row in rows)
    if args.json:
        emit({"command": "redact-verify", "file": args.report, "ok": ok, "reports": rows})
    else:
        for row in rows:
            if row["ok"]:
                mark = "clean" if row["clean"] else f"{row['findings']} finding(s)"
                console.print(f"[green]{row['state']}[/]  {row['run']}  {mark}")
            else:
                console.print(f"[red]failed[/]  {row['run'] or '-'}  {row['reason']}")
    if not ok:
        raise SystemExit(VERIFICATION_FAILED)


def _rules(args: argparse.Namespace) -> None:
    from opentine._redact_rules import export

    document = export()
    if args.json:
        emit({"command": "redact-rules", **document})
        return
    console.print(f"{document['ruleset']}  {document['digest']}")
    for rule in document["rules"]:
        console.print(f"{rule['order']:>3}  {rule['id']:<24} {rule['description']}")


def cmd_redact(args: argparse.Namespace) -> None:
    {"check": _check, "verify": _verify, "rules": _rules}[args.redact_command](args)


__all__ = ["add_redact_parser", "cmd_redact"]
