"""``tine cost`` flags for OTLP metrics and the signed cost statement (0.44)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from opentine import _cost_export
from opentine._cli_errors import USAGE, VERIFICATION_FAILED, fail


def add_cost_export_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--otlp", metavar="PATH", help="Write the cost aggregate as OTLP/JSON metrics ('-': stdout)"
    )
    parser.add_argument(
        "--statement", metavar="PATH", help="Write a tine-cost-statement/1 (with --sign-key)"
    )
    parser.add_argument("--sign-key", metavar="KEY", help="--statement: Ed25519 key file")
    parser.add_argument("--signer", help="--statement: the signer name to record")
    parser.add_argument(
        "--verify-statement", metavar="PATH", help="Check a cost statement against this run"
    )
    parser.add_argument("--pubkey", help="--verify-statement: trusted Ed25519 public key")


def _write(path: str, data: bytes) -> None:
    if path == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.flush()
    else:
        Path(path).write_bytes(data)


def handle_cost_export(args: argparse.Namespace, run: Any) -> bool:
    """Act on the export flags; returns whether one was given (the table is skipped)."""
    otlp, out, check = (
        getattr(args, name, None) for name in ("otlp", "statement", "verify_statement")
    )
    if not (otlp or out or check):
        if getattr(args, "sign_key", None) or getattr(args, "pubkey", None):
            fail("--sign-key needs --statement and --pubkey needs --verify-statement", USAGE)
        return False
    if otlp:
        _write(otlp, json.dumps(_cost_export.otlp_metrics(run), sort_keys=True).encode() + b"\n")
    if out:
        if not getattr(args, "sign_key", None):
            fail("--statement is a signed document: pass --sign-key KEY", USAGE)
        from opentine._signing_keys import ed25519_private_from_file

        try:
            key = ed25519_private_from_file(args.sign_key)
            doc = _cost_export.sign_statement(_cost_export.statement(run), key, args.signer)
        except (OSError, ValueError) as exc:
            fail(f"cannot sign the cost statement: {exc}", cause=exc)
        _write(out, _cost_export.dumps(doc))
    if check:
        from opentine._signing_keys import ed25519_public_from_file

        try:
            public = ed25519_public_from_file(args.pubkey) if args.pubkey else None
            result = _cost_export.verify_statement(_cost_export.load(check), run, public)
        except (OSError, ValueError) as exc:
            fail(f"cannot check the cost statement: {exc}", VERIFICATION_FAILED, cause=exc)
        print(json.dumps({"command": "cost verify-statement", **result}, sort_keys=True))
        if not result["ok"]:
            raise SystemExit(VERIFICATION_FAILED)
    return True
