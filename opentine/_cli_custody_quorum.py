"""``tine custody approve|revoke|approvals`` (0.91): k-of-n custody approvals.

``approve --operation copy|export --digest D [--checkpoint C] --requester FPR
--key K`` signs one ``opentine.custody-approval/1`` approval by a pinned
custodian key; ``revoke APPROVAL --key K`` revokes one (its signer or a pinned
policy key); ``approvals --operation O --digest D [--checkpoint C] --requester
FPR`` counts them and exits 1 when the quorum is short
(:mod:`opentine._custody_quorum`). Each takes ``--json``
(``tine-cli-custody-quorum/1``).
"""

from __future__ import annotations

import argparse
from typing import Any

SCHEMA = "tine-cli-custody-quorum/1"
VERBS = ("approve", "revoke", "approvals")


def add_quorum_parsers(actions: Any) -> None:
    from opentine._custody_quorum import OPERATIONS

    approve = actions.add_parser("approve", help="0.91: approve one custody export or copy")
    revoke = actions.add_parser("revoke", help="0.91: revoke a custody approval")
    revoke.add_argument("approval", metavar="ATTESTATION", help="The approval to revoke")
    count = actions.add_parser("approvals", help="0.91: count the approvals of one request")
    for verb in (approve, count):
        verb.add_argument("--operation", required=True, choices=OPERATIONS)
        verb.add_argument("--digest", required=True, help="sha256: of the exact bytes")
        verb.add_argument("--checkpoint", help="sha256: of the checkpoint the bytes cover")
        verb.add_argument("--requester", required=True, metavar="FPR",
                          help="sha256: fingerprint of the requester's key")  # fmt: skip
    approve.add_argument("--artifact", metavar="NAME", help="The artifact name (informative)")
    approve.add_argument("--destination", metavar="TEXT", help="Where it goes (informative)")
    for verb in (approve, revoke):
        verb.add_argument("--key", required=True, metavar="KEY", help="The signing key")
        verb.add_argument("--at", metavar="RFC3339", help="Signing time (default now)")
    for verb in (approve, revoke, count):
        verb.add_argument("--repo", default=".")
        verb.add_argument("--json", action="store_true", help="Emit a JSON object instead")


def _when(text: str | None) -> float | None:
    from datetime import datetime

    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp() if text else None


def _request(args: argparse.Namespace) -> dict[str, Any]:
    return {"operation": args.operation, "digest": args.digest, "checkpoint": args.checkpoint,
            "requester": args.requester}  # fmt: skip


def run_quorum(args: argparse.Namespace) -> None:
    from opentine import _custody_quorum as quorum
    from opentine._cli_common import _terminal, console
    from opentine._cli_errors import error
    from opentine._cli_json import emit
    from opentine._key_hygiene import ed25519_private
    from opentine.repo import Repo

    verb = args.custody_command
    try:
        repo = Repo.open(args.repo)
        if verb == "approve":
            oid = quorum.approve(repo, ed25519_private(args.key), **_request(args),
                                 artifact=args.artifact, destination=args.destination,
                                 now=_when(args.at))  # fmt: skip
            body, lines = {"record": oid, **_request(args)}, [f"approved: {oid}"]
        elif verb == "revoke":
            oid = quorum.revoke(repo, args.approval, ed25519_private(args.key),
                                now=_when(args.at))  # fmt: skip
            body, lines = {"record": oid, "approval": args.approval}, [f"revoked: {oid}"]
        else:
            found = quorum.tally(repo, **_request(args))
            body = {**_request(args), **{k: found[k] for k in ("required", "k", "counted",
                                                                "approvals", "ok")}}  # fmt: skip
            lines = [
                f"{found['counted']} of {found['k']} custodian approvals"
                + ("" if found["required"] else " (no quorum is required)")
            ]
            lines += [f"  {a['record']} {a['signer']} " + ("counted" if a["counted"]
                      else f"not counted: {a['why']}") for a in found["approvals"]]  # fmt: skip
    except quorum.QuorumError as exc:
        raise error(exc, 1, prefix=f"custody {verb}: ") from exc
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix=f"custody {verb}: ") from exc
    if args.json:
        emit({"command": f"custody {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if verb == "approvals" and not body["ok"]:
        raise SystemExit(1)


__all__ = ["SCHEMA", "VERBS", "add_quorum_parsers", "run_quorum"]
