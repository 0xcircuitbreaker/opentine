"""``tine witness cosign|vkey`` (0.44, X33) and ``tine scitt verify --experimental``.

``witness cosign CHECKPOINT --log-vkey V --key KEY --name N [--proof P | --tiles DIR]``
checks the checkpoint against the pinned log key and the last one this witness
cosigned for that origin (``--state``), refuses a fork or rollback (exit 4),
and prints the checkpoint with a C2SP ``cosignature/v1`` line added
(``_witness``). ``witness vkey --key KEY --name N`` prints the witness's
verifier key for others to pin with ``verify --witness-vkey``.

``scitt verify STATEMENT --key PEM [--receipt R]... [--service-key PEM]``
checks a COSE_Sign1 signed statement and its receipts offline (``_scitt``); it
refuses to run without ``--experimental``.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from opentine._cli_common import BRAND, console
from opentine._cli_errors import USAGE, VERIFICATION_FAILED, fail

MAX_INPUT = 1 << 20


def _state_default() -> str:
    home = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return str(Path(home, "opentine", "witness"))


def add_witness_parsers(sub: Any) -> None:
    witness = sub.add_parser("witness", help="Cosign a log checkpoint consistent with the last")
    actions = witness.add_subparsers(dest="witness_command", required=True)
    cosign = actions.add_parser("cosign", help="Check consistency, then add a cosignature")
    cosign.add_argument("checkpoint", metavar="CHECKPOINT", help="Signed-note checkpoint file")
    cosign.add_argument("--log-vkey", required=True, help="Pinned log key (name+hash+key)")
    cosign.add_argument("--proof", metavar="FILE", help="Consistency proof JSON from the last")
    cosign.add_argument("--tiles", metavar="DIR", help="Local tile mirror to compute the proof")
    cosign.add_argument("--state", help="Witness state directory (default: XDG state dir)")
    cosign.add_argument("--out", metavar="FILE", help="Write the cosigned checkpoint here")
    vkey = actions.add_parser("vkey", help="Print this witness's verifier key")
    for parser in (cosign, vkey):
        parser.add_argument("--key", required=True, metavar="KEY", help="Ed25519 key file")
        parser.add_argument("--name", required=True, help="Witness name (e.g. example.com/w1)")
        parser.add_argument("--json", action="store_true", help="Emit a JSON object instead")
    scitt = sub.add_parser("scitt", help="Verify SCITT signed statements offline (experimental)")
    scitt_actions = scitt.add_subparsers(dest="scitt_command", required=True)
    check = scitt_actions.add_parser("verify", help="Check a COSE_Sign1 statement and receipts")
    check.add_argument("statement", metavar="STATEMENT", help="COSE_Sign1 file (CBOR)")
    check.add_argument("--key", required=True, metavar="PEM", help="Issuer's pinned public key")
    check.add_argument("--receipt", action="append", default=[], metavar="FILE", help="Receipt")
    check.add_argument("--service-key", metavar="PEM", help="Transparency service public key")
    check.add_argument("--experimental", action="store_true", help="Required: interop unproven")
    check.add_argument("--json", action="store_true", help="Emit a JSON object instead")


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        data = handle.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ValueError(f"{path} exceeds {MAX_INPUT} bytes")
    return data


def cmd_witness(args: argparse.Namespace) -> None:
    from opentine import _witness
    from opentine._signing_keys import SignatureError, ed25519_private_from_file
    from opentine.repository._tlog_cosign import witness_vkey

    try:
        key = ed25519_private_from_file(args.key)
        if args.witness_command == "vkey":
            vkey = witness_vkey(args.name, key.public_key().public_bytes_raw())
            print(json.dumps({"vkey": vkey}) if args.json else vkey)
            return
        proof = _witness.load_proof(Path(args.proof)) if args.proof else None
        tiles = Path(args.tiles) if args.tiles else None
        state = Path(args.state or _state_default())
        note = _read(args.checkpoint)
    except (OSError, SignatureError, ValueError) as exc:
        fail(exc, prefix="tine witness: ", cause=exc)
    try:
        result = _witness.witness(
            note, args.log_vkey, key, args.name, state, proof=proof, tiles=tiles
        )
    except (OSError, ValueError) as exc:
        fail(exc, VERIFICATION_FAILED, prefix="tine witness: ", cause=exc)
    if args.out:
        Path(args.out).write_text(result["checkpoint"], encoding="utf-8")
    if args.json:
        print(json.dumps(result, sort_keys=True))
    elif args.out:
        console.print(f"[{BRAND}]# Cosigned[/] {result['origin']} at size {result['size']}")
    else:
        print(result["checkpoint"], end="")


def cmd_scitt(args: argparse.Namespace) -> None:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    from opentine import _scitt

    if not args.experimental:
        fail("SCITT verification is experimental; pass --experimental", USAGE)
    try:
        key = load_pem_public_key(_read(args.key))
        service = load_pem_public_key(_read(args.service_key)) if args.service_key else None
        receipts = [_read(path) for path in args.receipt]
        data = _read(args.statement)
    except (OSError, ValueError) as exc:
        fail(exc, prefix="tine scitt: ", cause=exc)
    try:
        result = _scitt.verify_statement(data, key, service_key=service, receipts=receipts)
    except ValueError as exc:
        fail(exc, VERIFICATION_FAILED, prefix="tine scitt verify: ", cause=exc)
    if args.json:
        print(json.dumps(result, sort_keys=True, default=repr))
        return
    console.print(f"[{BRAND}]# Verified[/] SCITT statement (experimental)")
    console.print(f"  issuer: {result['issuer']!r}  subject: {result['subject']!r}")
    for receipt in result["receipts"]:
        console.print(f"  receipt: leaf {receipt['leaf_index']} of {receipt['tree_size']}")


COMMANDS = {"scitt": cmd_scitt, "witness": cmd_witness}

__all__ = ["COMMANDS", "add_witness_parsers", "cmd_scitt", "cmd_witness"]
