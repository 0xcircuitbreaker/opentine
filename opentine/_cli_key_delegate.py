"""``tine key delegate`` and ``tine key delegation show|verify`` (0.43, X32).

* ``tine key delegate KEY --to PUB --agent NAME --action NAME [--max-depth N]
  [--not-before T] [--not-after T | --days N] [--parent CHAIN] --out CHAIN``:
  *KEY* (the principal, or a delegate holding *CHAIN*) signs an
  ``opentine-delegation/1`` certificate for *PUB*; ``--out`` gets the chain
  (the parent's certificates, then the new one), root first.
* ``tine key delegation show CHAIN`` prints each certificate.
* ``tine key delegation verify CHAIN --signer PUB|FPR [--at T] [--agent NAME]
  [--action NAME] [--root FPR]`` verifies the chain fully offline; exit 4 and
  the ``delegation.*`` code when it does not.

A run captured with ``OPENTINE_DELEGATION=CHAIN`` carries the chain, and
``tine verify --offline`` checks it against the run's signer (``_delegation_check``).
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from opentine._cli_errors import ERROR, USAGE, VERIFICATION_FAILED, fail


def add_delegate_parsers(verbs: Any) -> None:
    issue = verbs.add_parser("delegate", help="Delegate scoped authority to an agent key")
    issue.add_argument("key", metavar="KEY", help="The issuer's Ed25519 private key")
    issue.add_argument("--to", required=True, metavar="PUB", help="The delegate's public key")
    issue.add_argument("--agent", action="append", metavar="NAME", help="Allowed agent (*: any)")
    issue.add_argument("--action", action="append", metavar="NAME", help="Allowed tool (*: any)")
    issue.add_argument("--max-depth", type=int, default=0, help="Further delegations allowed")
    issue.add_argument("--not-before", metavar="TIME", help="RFC 3339 start (default: now)")
    issue.add_argument("--not-after", metavar="TIME", help="RFC 3339 end")
    issue.add_argument("--days", type=int, default=30, help="Window length without --not-after")
    issue.add_argument("--parent", metavar="CHAIN", help="The chain KEY was delegated by")
    issue.add_argument("--out", required=True, metavar="CHAIN", help="Write the new chain here")
    issue.add_argument("--json", action="store_true", help="Print a JSON object")
    show = verbs.add_parser("delegation", help="Show or verify a delegation chain")
    show.add_argument("delegation_command", choices=("show", "verify"))
    show.add_argument("chain", metavar="CHAIN", help="A chain file from tine key delegate")
    show.add_argument("--signer", metavar="PUB|FPR", help="verify: the key that signed the work")
    show.add_argument("--at", metavar="TIME", help="verify: when it was signed (default: now)")
    show.add_argument("--agent", metavar="NAME", help="verify: the agent that must be delegated")
    show.add_argument("--action", action="append", metavar="NAME", help="verify: a used tool")
    show.add_argument("--root", metavar="FPR", help="verify: the only trusted root issuer")
    show.add_argument("--json", action="store_true", help="Print a JSON object")


def read_chain(path: str) -> list[Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [data] if isinstance(data, dict) else data if isinstance(data, list) else []


def _fingerprint(value: str) -> str:
    from opentine._signing_keys import ed25519_public_from_file
    from opentine._signing_pins import key_fingerprint, normalize_pin

    if Path(value).is_file():
        return key_fingerprint(ed25519_public_from_file(value).public_bytes_raw())
    return normalize_pin(value)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _issue(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._canon import atomic_write_text
    from opentine._delegation import issue
    from opentine._key_lifecycle import parse_time, stamp
    from opentine._signing_keys import ed25519_private_from_file, ed25519_public_from_file

    if not args.agent or not args.action:
        fail("name what is delegated: at least one --agent and one --action", USAGE)
    parent = read_chain(args.parent) if args.parent else []
    start = args.not_before or _now()
    end = args.not_after or stamp(parse_time(start) + timedelta(days=args.days))
    cert = issue(ed25519_private_from_file(args.key, signer=False),
                 ed25519_public_from_file(args.to).public_bytes_raw(),
                 agents=args.agent, actions=args.action, max_depth=args.max_depth,
                 not_before=start, not_after=end,
                 parent=parent[-1] if parent else None)  # fmt: skip
    chain = [*parent, cert]
    atomic_write_text(Path(args.out), json.dumps(chain, indent=2, sort_keys=True) + "\n")
    return {"out": str(args.out), "depth": len(chain), "certificate": cert}


def cmd_key_delegate(args: argparse.Namespace) -> None:
    from opentine._cli_common import _terminal, console
    from opentine._cli_json import emit
    from opentine._delegation import DelegationError, summary
    from opentine._delegation_verify import verify_chain
    from opentine._key_store import PassphraseUnavailable
    from opentine._signing_keys import SignatureError

    verb = "delegate" if args.key_command == "delegate" else f"delegation {args.delegation_command}"
    errors = (DelegationError, OSError, PassphraseUnavailable, SignatureError, ValueError)
    try:
        if verb == "delegate":
            row = _issue(args)
        elif verb == "delegation show":
            row = {"certificates": [summary(cert) for cert in read_chain(args.chain)]}
        else:
            if not args.signer:
                fail("delegation verify needs --signer PUB|FPR", USAGE)
            root = _fingerprint(args.root) if args.root else None
            row = verify_chain(read_chain(args.chain), signer=_fingerprint(args.signer),
                               at=args.at or _now(), agent=args.agent,
                               actions=args.action or (), root=root)  # fmt: skip
            row = {"ok": True, **row}
    except DelegationError as exc:
        if args.json:
            emit({"command": f"key {verb}", "ok": False, "reason": exc.code, "detail": str(exc)})
            raise SystemExit(VERIFICATION_FAILED) from exc
        fail(f"DELEGATION FAILED {exc.code}: {exc}", VERIFICATION_FAILED)
    except errors as exc:
        fail(exc, ERROR, prefix=f"key {verb}: ", cause=exc)
    if args.json:
        emit({"command": f"key {verb}", **row})
        return
    if verb == "delegate":
        cert = row["certificate"]
        console.print(f"delegated {cert['issuer']} -> {cert['subject']} (chain depth "
                      f"{row['depth']}) to {_terminal(row['out'])}", highlight=False)  # fmt: skip
    elif verb == "delegation show":
        for index, cert in enumerate(row["certificates"]):
            console.print(f"[{index}] {cert['digest']}", highlight=False, markup=False)
            for name in ("issuer", "subject", "not_before", "not_after", "parent", "scope"):
                console.print(f"    {name:<10} {_terminal(cert[name])}", markup=False)
    else:
        console.print(f"DELEGATION OK root {row['root']} -> signer {row['signer']} "
                      f"({len(row['links'])} link(s))", highlight=False)  # fmt: skip


__all__ = ["add_delegate_parsers", "cmd_key_delegate", "read_chain"]
