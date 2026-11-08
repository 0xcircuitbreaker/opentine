"""``tine purge OID --reason TEXT`` and ``tine purge --list`` (0.46).

``tine purge`` removes one blob's bytes from the repository and keeps its oid,
leaving a signed ``opentine.tombstone`` (SPEC 4.14, :mod:`opentine._tombstone`)
that says why, who and when. The tombstone is signed here, with the operator's
key (``--key-file`` HMAC or ``--ed25519-key-file``): a purge without a key is
refused, and no server ever signs one. The bytes go through the prune
quarantine (:mod:`opentine.repository._purge`).

``--list`` prints every tombstone with ``content: unavailable`` (or
``present``, for a record imported beside a copy still held) and its trust:
``--key-file``/``--pubkey`` check each signature, with neither an Ed25519
record rests on its embedded key (``verified-tofu``) and an HMAC one is
``unchecked``. It exits 4 when a record fails.
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine._cli_common import console
from opentine._cli_errors import NOT_FOUND, VERIFICATION_FAILED, fail
from opentine._cli_json import emit


def add_purge_parser(sub: Any) -> None:
    purge = sub.add_parser(
        "purge", help="Remove a blob's bytes, keep its oid, leave a signed tombstone"
    )
    purge.add_argument("oid", nargs="?", metavar="OID", help="The blob to purge (blob:sha256:…)")
    purge.add_argument("--reason", help="Why the bytes are removed (redacted, then signed)")
    purge.add_argument("--actor", help="Who purges (default: --key-id, else 'local')")
    purge.add_argument("--list", action="store_true", help="List and check every tombstone")
    keys = purge.add_mutually_exclusive_group()
    keys.add_argument("--key-file", metavar="PATH", help="HMAC key: sign, or check with --list")
    keys.add_argument("--ed25519-key-file", metavar="PATH", help="Sign with this Ed25519 key")
    keys.add_argument("--pubkey", metavar="PATH", help="--list: trusted Ed25519 public key")
    purge.add_argument("--key-id", help="Key id recorded in the tombstone signature")
    purge.add_argument("--repo", default=".")
    purge.add_argument("--json", action="store_true")


def _signed(args: argparse.Namespace, oid: str) -> dict[str, Any]:
    from opentine import _tombstone
    from opentine._signing_keys import ed25519_private_from_file, hmac_key_from_file

    if not args.reason or not args.reason.strip():
        raise ValueError("tine purge needs --reason TEXT")
    if args.key_file:
        key, algorithm = hmac_key_from_file(args.key_file), "hmac-sha256"
    elif args.ed25519_key_file:
        key, algorithm = ed25519_private_from_file(args.ed25519_key_file), "ed25519"
    else:
        raise ValueError("a tombstone is signed: pass --key-file or --ed25519-key-file")
    actor = args.actor or args.key_id or "local"
    body = _tombstone.build(oid, args.reason, actor)
    return _tombstone.sign(body, key, algorithm=algorithm, key_id=args.key_id)


def _purge(args: argparse.Namespace) -> None:
    from opentine.repository import Repo
    from opentine.repository._purge import purge

    if args.pubkey:
        raise ValueError("--pubkey checks tombstones with --list; sign with --ed25519-key-file")
    repo = Repo.open(args.repo)
    record = _signed(args, args.oid)
    try:
        result = purge(repo, record)
    except KeyError as exc:
        fail(str(exc.args[0] if exc.args else exc), NOT_FOUND)
    if args.json:
        emit({"command": "purge", **result, "tombstone": record})
    elif result["already"]:
        console.print(f"already purged: {result['oid']}")
    else:
        console.print(f"[green]purged[/] {result['oid']} (content-unavailable; tombstone kept)")


def _row(repo: Any, oid: str, hmac: bytes | None, public: bytes | None) -> dict[str, Any]:
    from opentine import _tombstone
    from opentine._signed_record import RecordError
    from opentine.repository import _tombstones

    content = "present" if repo.has(oid) else "unavailable"
    row: dict[str, Any] = {"oid": oid, "content": content, "actor": None, "purged_at": None}
    try:
        record = _tombstones.read(repo, oid)
        assert record is not None
        row.update(actor=record["actor"], purged_at=record["purged_at"])
        alg = record["signature"].get("alg")
        if alg == "hmac-sha256" and hmac is None:
            return {**row, "state": "unchecked", "reason": None}
        found = _tombstone.check(record, hmac_key=hmac, public_key=public)
        return {**row, "state": found["state"], "reason": None}
    except RecordError as exc:
        return {**row, "state": "failed", "reason": exc.code}
    except (OSError, ValueError) as exc:
        return {**row, "state": "failed", "reason": f"tombstone.malformed: {exc}"[:200]}


def _list(args: argparse.Namespace) -> None:
    from opentine._signing_keys import ed25519_public_from_file, hmac_key_from_file
    from opentine.repository import Repo, _tombstones

    repo = Repo.open(args.repo)
    hmac = hmac_key_from_file(args.key_file) if args.key_file else None
    public = ed25519_public_from_file(args.pubkey).public_bytes_raw() if args.pubkey else None
    rows = [_row(repo, oid, hmac, public) for oid in _tombstones.listed(repo)]
    ok = all(row["state"] != "failed" for row in rows)
    if args.json:
        emit({"command": "purge-list", "ok": ok, "tombstones": rows})
    else:
        for row in rows:
            color = "red" if row["state"] == "failed" else "green"
            why = f"  {row['reason']}" if row["reason"] else ""
            console.print(
                f"{row['oid']}  content-{row['content']}  [{color}]{row['state']}[/]"
                f"  {row['actor'] or '-'}  {row['purged_at'] or '-'}{why}"
            )
        console.print(f"{len(rows)} tombstone(s)")
    if not ok:
        raise SystemExit(VERIFICATION_FAILED)


def cmd_purge(args: argparse.Namespace) -> None:
    if args.list:
        if args.oid or args.reason or args.ed25519_key_file:
            raise ValueError("--list takes no OID, --reason or signing key")
        return _list(args)
    if not args.oid:
        raise ValueError("name the blob to purge (tine purge OID --reason TEXT), or pass --list")
    return _purge(args)


__all__ = ["add_purge_parser", "cmd_purge"]
