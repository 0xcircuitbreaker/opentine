"""``tine fleet record``: a run's ``opentine-fleet/1`` record, signed or attested (0.43).

* ``tine fleet record RUN.tine`` prints the record capture stored from
  ``OPENTINE_FLEET_*`` (``_fleet_record``) and the run's delegation chain, if any.
* ``--sign-key KEY --out FILE`` writes an ``opentine-fleet-record/1`` document:
  the record bound to the run's id and digest under a ``tine-sig/3`` block.
* ``--attest OUT --attest-key KEY`` writes an in-toto ``fleet/v1`` DSSE
  envelope (``_intoto_fleet``) whose subject is the run's digest.
* ``tine fleet record FILE`` on a signed record verifies it offline (exit 4 on
  failure); ``--pubkey PUB`` requires that key, else the embedded one is TOFU.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from opentine._cli_errors import ERROR, USAGE, VERIFICATION_FAILED, fail


def add_record_args(parser: Any) -> None:
    parser.add_argument("--sign-key", metavar="KEY", help="record: sign the fleet record")
    parser.add_argument("--out", metavar="FILE", help="record: where --sign-key writes")
    parser.add_argument("--attest", metavar="OUT", help="record: write a fleet/v1 DSSE envelope")
    parser.add_argument("--attest-key", metavar="KEY", help="record: Ed25519 key for --attest")
    parser.add_argument("--pubkey", metavar="PUB", help="record: key a signed record must use")


def _emit(args: argparse.Namespace, row: dict[str, Any], lines: list[str]) -> None:
    from opentine._cli_common import _terminal, console

    if args.json:
        sys.stdout.write(json.dumps({"command": "fleet record", **row}) + "\n")
        return
    for line in lines:
        console.print(_terminal(line), markup=False, highlight=False)


def _verify_document(args: argparse.Namespace, document: dict[str, Any]) -> int:
    from opentine._fleet_record import verify
    from opentine._signing_keys import ed25519_public_from_file

    key = ed25519_public_from_file(args.pubkey) if args.pubkey else None
    ok, detail = verify(document, key)
    row = {"verified": ok, "detail": detail, "record": document.get("record"),
           "run_id": document.get("run_id"), "run_digest": document.get("run_digest")}  # fmt: skip
    state = "FLEET RECORD OK" if ok else "FLEET RECORD FAILED"
    _emit(args, row, [f"{state}: {detail}", f"run {row['run_id']} {row['run_digest']}"])
    return 0 if ok else VERIFICATION_FAILED


def _write(path: str, document: dict[str, Any]) -> None:
    from opentine._export_write import write_private

    line = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    write_private(Path(path), line.encode("utf-8"))


def record(args: argparse.Namespace) -> int:
    from opentine import _fleet_record
    from opentine._intoto_fleet import build_statement
    from opentine._signing_keys import SignatureError, ed25519_private_from_file
    from opentine.core import Run
    from opentine.intoto import sign_statement

    if not args.target:
        fail("record needs a RUN artifact or a signed fleet record", USAGE)
    try:
        data = json.loads(Path(args.target).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        data = None
    if isinstance(data, dict) and data.get("scheme") == _fleet_record.SIGNED_SCHEME:
        return _verify_document(args, data)
    if bool(args.sign_key) != bool(args.out) or bool(args.attest) != bool(args.attest_key):
        fail("--sign-key goes with --out, and --attest with --attest-key", USAGE)
    integrity = Run.verify_integrity(args.target)
    if not integrity.ok or not isinstance(integrity.actual, str):
        fail(f"cannot read the run: integrity fails ({integrity.reason})")
    run = Run.load(args.target)
    found = _fleet_record.run_record(run)
    if found is None:
        fail("that run has no opentine-fleet/1 record (captured without OPENTINE_FLEET_ID)")
    chain = run.metadata.get("delegation") if isinstance(run.metadata, dict) else None
    row: dict[str, Any] = {"run_id": run.id, "run_digest": integrity.actual, "record": found,
                           "delegation": len(chain) if isinstance(chain, list) else 0}  # fmt: skip
    try:
        if args.sign_key:
            key = ed25519_private_from_file(args.sign_key, signer=False)
            _write(args.out, _fleet_record.sign(found, run.id, integrity.actual, key))
            row["out"] = args.out
        if args.attest:
            key = ed25519_private_from_file(args.attest_key, signer=False)
            _write(args.attest, sign_statement(build_statement(run, found, integrity.actual), key))
            row["attest"] = args.attest
    except (OSError, SignatureError, ValueError) as exc:
        fail(f"fleet record: {exc}", ERROR, cause=exc)
    lines = [f"fleet {found['fleet_id']} member {found['member']} role {found['role']}"
             + (f" parent {found['parent']}" if found["parent"] else ""),
             f"run {run.id} {integrity.actual}; delegation links: {row['delegation']}"]  # fmt: skip
    lines += [f"wrote {row[k]}" for k in ("out", "attest") if k in row]
    _emit(args, row, lines)
    return 0


__all__ = ["add_record_args", "record"]
