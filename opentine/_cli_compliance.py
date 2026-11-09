"""``tine compliance list|check``: map a run's evidence onto a legal profile (0.48).

``tine compliance check RUN --profile NAME`` runs the offline verifier
(``tine verify RUN --offline`` with the key, TSA and attestation flags given
here), reads ``--repo``'s retention policy and custody log, and reports each
requirement of the profile (:mod:`opentine._compliance`) as ``evidenced``,
``missing`` or ``out-of-scope``. ``--profile`` also takes a path to a profile
file. Every output carries the notice "draft — not legal advice, pending
counsel review". The command exits 0 whatever the result, unless ``--strict``:
then a missing in-scope requirement exits 4 (verification_failed).
"""

from __future__ import annotations

import argparse
import re
from typing import Any

from opentine._cli_errors import NOT_FOUND, USAGE, VERIFICATION_FAILED, fail

_PASS = (("pubkey", "--pubkey"), ("tsa_roots", "--tsa-roots"), ("attestation", "--attestation"),
         ("rekor_key", "--rekor-key"), ("trusted_root", "--trusted-root"))  # fmt: skip


def add_compliance_parser(sub: Any) -> None:
    comp = sub.add_parser("compliance", help="Check a run against a compliance profile (draft)")
    verbs = comp.add_subparsers(dest="compliance_command", required=True)
    listing = verbs.add_parser("list", help="List the compliance profiles")
    listing.add_argument("--json", action="store_true", help="Print a JSON object")
    check = verbs.add_parser("check", help="Report which requirements a run evidences")
    check.add_argument("run_id", help="Run: a .tine file, or an id under .tine_runs")
    check.add_argument("--profile", required=True, metavar="NAME", help="Profile name or file")
    check.add_argument("--repo", metavar="DIR", help="Repository whose retention and custody count")
    check.add_argument("--pubkey", metavar="FILE", help="Trusted Ed25519 key of the run's signer")
    check.add_argument("--pin", action="append", metavar="FINGERPRINT", help="Pin an embedded key")
    check.add_argument("--tsa-roots", metavar="FILE.pem", help="Trusted TSA roots for tokens")
    check.add_argument("--attestation", metavar="FILE", help="in-toto attestation for the run")
    check.add_argument("--rekor-key", metavar="FILE", help="Rekor log key for its receipt")
    check.add_argument("--trusted-root", metavar="FILE", help="Sigstore trusted_root.json")
    check.add_argument("--proxy-pubkey", action="append", metavar="FILE", help="Proxy witness key")
    check.add_argument("--strict", action="store_true", help="Exit 4 if any requirement is missing")
    check.add_argument("--json", action="store_true", help="Print a JSON object")


def _verify_args(args: argparse.Namespace, path: str) -> argparse.Namespace:
    from opentine._cli_parser import _build_parser

    argv = ["verify", path, "--offline"]
    for dest, flag in _PASS:
        if getattr(args, dest, None):
            argv += [flag, getattr(args, dest)]
    for fpr in args.pin or []:
        argv += ["--pin", fpr]
    for key in args.proxy_pubkey or []:
        argv += ["--proxy-pubkey", key]
    return _build_parser().parse_args(argv)


def build(args: argparse.Namespace) -> dict[str, Any]:
    """The ``compliance-check`` document (without ``command``)."""
    from pathlib import Path

    from opentine import _compliance, _compliance_facts
    from opentine._cli_common import _find_run
    from opentine._verify_chain import _read, build_report

    profile = _compliance.load(args.profile)
    path = _find_run(args.run_id)
    if not path:
        fail(f"run not found: {args.run_id}", NOT_FOUND, prefix="tine compliance: ")
    verified = build_report(_verify_args(args, str(path)), Path(path), args.run_id)
    report = verified.as_json()
    _, run = _read(Path(path))
    signer = any(c.name == "signature" and c.outcome == "pass" and c.authenticates
                 for c in verified.checks)  # fmt: skip
    facts = _compliance_facts.from_report(report, run, signer_authenticated=signer)
    digest = next((c for c in verified.checks if c.name == "digest"), None)
    found = re.search(r"sha256:([0-9a-f]{64})", digest.detail) if digest else None
    run_digest = found.group(1) if found and digest.outcome == "pass" else None
    facts.update(_compliance_facts.repo_facts(args.repo, run_digest))
    body = _compliance.evaluate(profile, facts)
    return {"run": str(getattr(run, "id", "") or args.run_id), **body}


def cmd_compliance(args: argparse.Namespace) -> None:
    from opentine import _compliance
    from opentine._cli_json import emit

    try:
        if args.compliance_command == "list":
            rows = [_row(name, _compliance.load(name)) for name in _compliance.available()]
            if args.json:
                return emit({"command": "compliance-list", "notice": _compliance.NOTICE,
                             "profiles": rows})  # fmt: skip
            return _print_list(rows)
        document = build(args)
    except _compliance.ProfileError as exc:
        fail(exc, USAGE, prefix="tine compliance: ")
    if args.json:
        emit({"command": "compliance-check", **document})
    else:
        _print_check(document)
    if args.strict and document["summary"]["missing"]:
        raise SystemExit(VERIFICATION_FAILED)


def _row(name: str, profile: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "title": profile["title"], "profile_version": profile["profile_version"],
            "requirements": len(profile["requirements"]),
            "counsel_review": profile["counsel_review"]}  # fmt: skip


def _print_list(rows: list[dict[str, Any]]) -> None:
    from opentine._cli_common import console
    from opentine._compliance import NOTICE

    console.print(f"[yellow]{NOTICE}[/]")
    for row in rows:
        console.print(f"{row['name']:<10} {row['requirements']:>2} requirements  {row['title']}")


def _print_check(doc: dict[str, Any]) -> None:
    from rich.markup import escape

    from opentine._cli_common import console

    colors = {"evidenced": "green", "missing": "red", "out-of-scope": "dim"}
    console.print(f"[yellow]{escape(doc['notice'])}[/] (counsel review: {doc['counsel_review']})")
    console.print(f"{escape(doc['title'])}  run {escape(doc['run'])}")
    for row in doc["requirements"]:
        color = colors[row["status"]]
        console.print(
            f"[{color}]{row['status']:>12}[/]  {escape(row['cite'])}: {escape(row['id'])}"
        )
        for item in row["evidence"]:
            if item["status"] != "evidenced":
                console.print(f"{'':>14}{item['fact']}: {escape(item['detail'])}")
    s = doc["summary"]
    console.print(f"{s['evidenced']} evidenced, {s['missing']} missing, "
                  f"{s['out-of-scope']} out of scope")  # fmt: skip


COMMANDS = {"compliance": cmd_compliance}

__all__ = ["COMMANDS", "add_compliance_parser", "build", "cmd_compliance"]
