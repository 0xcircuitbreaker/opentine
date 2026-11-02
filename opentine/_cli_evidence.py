"""``tine evidence export RUN... --out DIR [--sign KEY]``: a portable evidence folder.

Each run is verified offline (``tine verify --offline --locate`` with the given
``--pubkey``/``--pin``/``--action-policy``) and written beside its report,
timeline, trust material and a chain-of-custody record; see
:mod:`opentine._evidence_export` for the layout and what is deterministic.
``--attestation`` (one run only) and ``--trusted-root`` feed the attestation
checks and are copied into ``trust/`` beside the key and policy. ``--sign``
takes an Ed25519 key file (``tine keygen``) and signs the custody record.
The command exits 1 when any run fails verification, after writing.
"""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path
from typing import Any

from opentine._cli_common import _find_run, _terminal, console


def add_evidence_parser(sub: Any) -> None:
    evidence = sub.add_parser("evidence", help="Export runs as a verifiable evidence folder")
    actions = evidence.add_subparsers(dest="evidence_command", required=True)
    export = actions.add_parser("export", help="Write runs, reports, timeline and custody")
    export.add_argument("runs", nargs="+", metavar="RUN", help="Run ids or .tine paths")
    export.add_argument("--out", required=True, metavar="DIR", help="New or empty directory")
    export.add_argument("--sign", metavar="KEY", help="Ed25519 key file: sign custody.jsonl")
    export.add_argument("--pubkey", help="Trusted Ed25519 public key for the run signatures")
    export.add_argument("--pin", action="append", metavar="FINGERPRINT", help="Pinned key")
    export.add_argument("--action-policy", metavar="FILE", help="Action policy to check")
    export.add_argument("--attestation", metavar="FILE", help="in-toto attestation (one run)")
    export.add_argument("--trusted-root", metavar="FILE", help="Sigstore trusted_root.json")
    export.add_argument("--operator", help="Who is exporting (default: the login name)")


def _fail(message: str) -> None:
    console.print(f"[red]{_terminal(message)}[/]")
    raise SystemExit(1)


def _verify_args(args: argparse.Namespace) -> argparse.Namespace:
    return argparse.Namespace(
        pubkey=args.pubkey,
        pin=args.pin,
        action_policy=args.action_policy,
        locate=True,
        strict=False,
        attestation=args.attestation,
        trusted_root=args.trusted_root,
    )


def cmd_evidence(args: argparse.Namespace) -> None:
    from opentine._evidence_export import write_evidence
    from opentine._signing_keys import SignatureError, ed25519_private_from_file
    from opentine._verify_chain import _read, build_report
    from opentine._version import __version__

    out = Path(args.out)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        _fail(f"--out must be a new or empty directory: {out}")
    try:
        key = ed25519_private_from_file(args.sign) if args.sign else None
    except (OSError, SignatureError, ValueError) as exc:
        _fail(f"cannot read --sign key: {exc}")
    sources: list[Path] = []
    for name in args.runs:
        path = _find_run(name)
        if path is None:
            _fail(f"Run not found: {name}")
        if any(p.name == Path(path).name for p in sources):
            _fail(f"two runs share the file name {Path(path).name}; export them separately")
        sources.append(Path(path))
    if args.trusted_root and not args.attestation:
        _fail("--trusted-root checks a keyless --attestation; pass one or drop it")
    if args.attestation and len(sources) != 1:
        _fail("--attestation names one run's subject; export that run on its own")
    verify = _verify_args(args)
    runs = [(p, _read(p)[0], build_report(verify, p, str(p)).as_json()) for p in sources]
    trust = {"pubkey.pub": Path(args.pubkey)} if args.pubkey else {}
    if args.action_policy:
        trust["action-policy" + Path(args.action_policy).suffix] = Path(args.action_policy)
    if args.attestation:
        trust["attestation.intoto.jsonl"] = Path(args.attestation)
    if args.trusted_root:
        trust["trusted_root.json"] = Path(args.trusted_root)
    operator = args.operator or _login()
    try:
        result = write_evidence(
            out, runs, trust_files=trust, operator=operator, version=__version__, signing_key=key
        )
    except OSError as exc:
        _fail(f"cannot write evidence: {exc}")
        return
    signed = " (custody signed)" if result["signed"] else ""
    console.print(f"Exported {result['runs']} run(s) to {_terminal(out)}{signed}")
    if not result["ok"]:
        console.print(
            "[red]at least one run FAILED offline verification; see verify-report.json[/]"
        )
        raise SystemExit(1)


def _login() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError):
        return "unknown"


COMMANDS = {"evidence": cmd_evidence}

__all__ = ["COMMANDS", "add_evidence_parser", "cmd_evidence"]
