"""``tine custody record|log|verify``: the chain of custody (0.39, ``_custody``).

``record ACTION SUBJECT --sign-key KEY`` appends a record signed with the
actor's Ed25519 key (``tine keygen``); ``record timestamp SIG_BOUND --token
T.tsr`` stores an RFC 3161 token over an earlier record's ``sig_bound`` (shown
by ``log``). ``verify`` checks the log offline and exits 4 when anything is
broken; ``--pubkey`` pins the actors' key and ``--vkey`` the checkpoint key.
"""

from __future__ import annotations

import argparse
import getpass
import json
from typing import Any

from opentine._cli_common import BRAND, _terminal, console
from opentine._cli_errors import VERIFICATION_FAILED, fail
from opentine._signing_keys import SignatureError


def add_custody_parser(sub: Any) -> None:
    custody = sub.add_parser("custody", help="Record and verify a signed chain of custody")
    actions = custody.add_subparsers(dest="custody_command", required=True)
    rec = actions.add_parser("record", help="Append a signed custody record")
    rec.add_argument("action", help="received, exported, verified, transferred, stored, timestamp")
    rec.add_argument("subject", help="What it concerns: a digest, run root or sig:sha256: binding")
    rec.add_argument("--sign-key", required=True, metavar="KEY", help="Actor's Ed25519 key file")
    rec.add_argument("--actor", help="Who acted (default: the login name)")
    rec.add_argument("--note", default="", help="Free text kept in the signed record")
    rec.add_argument("--token", metavar="TOKEN.tsr", help="timestamp: the TSA response")
    log = actions.add_parser("log", help="List custody records, oldest first")
    verify = actions.add_parser("verify", help="Check the log, chain, signatures and tokens")
    verify.add_argument("--pubkey", help="Trusted Ed25519 public key of every actor")
    verify.add_argument("--vkey", help="Pin the checkpoint key (signed-note name+hash+key)")
    verify.add_argument("--tsa-roots", metavar="FILE.pem", help="Trusted TSA roots")
    verify.add_argument("--trusted-root", metavar="FILE", help="Sigstore trusted_root.json")
    for parser in (rec, log, verify):
        parser.add_argument("--repo", default=".")
        parser.add_argument("--json", action="store_true", help="Emit a JSON object instead")


def _actor() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no login name (containers, services)
        return "local"


def _record(args: argparse.Namespace, base: Any) -> None:
    from opentine import _custody
    from opentine._signing_keys import ed25519_private_from_file

    try:
        key = ed25519_private_from_file(args.sign_key)
        token = None
        if args.token:
            with open(args.token, "rb") as handle:
                token = handle.read(_custody.MAX_TOKEN + 1)
        rec = _custody.record(
            base, args.action, args.subject, key, actor=args.actor or _actor(), note=args.note,
            token=token,
        )  # fmt: skip
    except (OSError, SignatureError, ValueError) as exc:
        fail(exc, prefix="tine custody: ", cause=exc)
    if args.json:
        print(json.dumps(rec, sort_keys=True))
        return
    console.print(f"[{BRAND}]# Recorded[/] {rec['id']} {rec['action']} (index {rec['index']})")
    console.print(f"  sig_bound: {rec['sig_bound']}")


def cmd_custody(args: argparse.Namespace) -> None:
    from opentine import _custody
    from opentine._cli_du import _repo

    try:
        base = _repo(args.repo).path
    except (KeyError, OSError, ValueError) as exc:
        fail(exc, prefix="tine custody: ", cause=exc)
    if args.custody_command == "record":
        _record(args, base)
        return
    if args.custody_command == "log":
        try:
            records = _custody.read(base)
        except (OSError, ValueError) as exc:
            fail(exc, VERIFICATION_FAILED, prefix="tine custody: ", cause=exc)
        if args.json:
            print(json.dumps({"records": records}, sort_keys=True))
            return
        for rec in records:
            who = _terminal(rec["actor"])
            what = _terminal(rec["subject"])
            console.print(f"[{BRAND}]{rec['id']}[/] {rec['time']} {who} {rec['action']} {what}")
            console.print(f"  sig_bound: {rec['sig_bound']}")
        return
    public_key = None
    try:
        if args.pubkey:
            from opentine._signing_keys import ed25519_public_from_file

            public_key = ed25519_public_from_file(args.pubkey)
        result = _custody.verify(base, args, vkey=args.vkey, public_key=public_key)
    except (OSError, SignatureError, ValueError) as exc:
        fail(exc, VERIFICATION_FAILED, prefix="tine custody verify: ", cause=exc)
    if args.json:
        print(json.dumps(result, sort_keys=True))
        return
    console.print(f"[{BRAND}]# Verified[/] custody log of {result['size']} record(s)")
    console.print(f"  signatures: {result['basis']}")
    for rec in result["records"]:
        if rec.get("signing_time"):
            console.print(f"  {rec['id']}: verified signing time {rec['signing_time']}")


COMMANDS = {"custody": cmd_custody}

__all__ = ["COMMANDS", "add_custody_parser", "cmd_custody"]
