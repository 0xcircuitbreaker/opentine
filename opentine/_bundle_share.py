"""``tine bundle create --redacted-public`` and what ``bundle verify`` says of 0.46 keys.

``create FILE REF --redacted-public --key-file K | --ed25519-key-file K`` bundles
the redacted copy of the one run REF names (:mod:`opentine._redacted_derive`)
under REF, with its ``opentine.redacted-copy`` record signed here by the
caller's key (a server never signs one). ``verify`` reports a bundle's
tombstones (the oids whose content is unavailable) and, for a public copy, the
record's check: under ``--key-file``/``--pubkey``, else an Ed25519 record on its
embedded key (``verified-tofu``) and an HMAC one ``unchecked``. A record that
fails makes ``verify`` exit 4.
"""

from __future__ import annotations

import argparse
from typing import Any


def add_create_flags(create: argparse.ArgumentParser) -> None:
    create.add_argument(
        "--redacted-public",
        action="store_true",
        help="Bundle one run's redacted copy, linked to it by a signed record",
    )
    keys = create.add_mutually_exclusive_group()
    keys.add_argument("--key-file", metavar="PATH", help="--redacted-public: sign (HMAC key)")
    keys.add_argument("--ed25519-key-file", metavar="PATH", help="--redacted-public: sign")
    create.add_argument("--key-id", help="--redacted-public: key id recorded in the signature")


def add_verify_flags(verify: argparse.ArgumentParser) -> None:
    keys = verify.add_mutually_exclusive_group()
    keys.add_argument("--key-file", metavar="PATH", help="HMAC key for a redacted-copy record")
    keys.add_argument("--pubkey", metavar="PATH", help="Trusted Ed25519 key for that record")


def refuse_keys(args: argparse.Namespace) -> None:
    if args.key_file or args.ed25519_key_file or args.key_id:
        raise ValueError("--key-file, --ed25519-key-file and --key-id sign --redacted-public")


def create_public(repo: Any, args: argparse.Namespace) -> bytes:
    from opentine._redacted_derive import public_bundle
    from opentine._signing_keys import ed25519_private_from_file, hmac_key_from_file
    from opentine.repository._refs import normalize_ref

    if args.all or len(args.refs) != 1:
        raise ValueError("--redacted-public bundles exactly one run: name one ref")
    if args.transparency:
        raise ValueError("--transparency receipts name private refs; not with --redacted-public")
    name = args.refs[0]
    ref = normalize_ref(name if "/" in name else f"heads/{name}")
    run = repo.read_ref(ref)
    if not run or not run.startswith("run:"):
        raise KeyError(f"no such run ref: {name}")
    if args.key_file:
        key, algorithm = hmac_key_from_file(args.key_file), "hmac-sha256"
    elif args.ed25519_key_file:
        key, algorithm = ed25519_private_from_file(args.ed25519_key_file), "ed25519"
    else:
        raise ValueError("--redacted-public signs: pass --key-file or --ed25519-key-file")
    return public_bundle(
        repo, ref, run, key, algorithm=algorithm, key_id=args.key_id, pack_format=args.pack_format
    )


def verified(checked: Any, args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _redacted_copy
    from opentine._signed_record import RecordError
    from opentine._signing_keys import ed25519_public_from_file, hmac_key_from_file

    out: dict[str, Any] = {}
    if checked.tombstones:
        out["content_unavailable"] = [record["oid"] for record in checked.tombstones]
    record = checked.redacted_public
    if record is None:
        return out
    hmac = hmac_key_from_file(args.key_file) if getattr(args, "key_file", None) else None
    pubkey = getattr(args, "pubkey", None)
    public = ed25519_public_from_file(pubkey).public_bytes_raw() if pubkey else None
    body = _redacted_copy.body(record)
    row = {k: body[k] for k in ("source_run", "public_run", "objects", "redacted", "ruleset")}
    if record["signature"].get("alg") == "hmac-sha256" and hmac is None:
        out["redacted_public"] = {**row, "state": "unchecked", "reason": None}
        return out
    try:
        found = _redacted_copy.check(record, hmac_key=hmac, public_key=public, pack=body["pack"])
        out["redacted_public"] = {**row, "state": found["state"], "reason": None}
    except RecordError as exc:
        out["redacted_public"] = {**row, "state": "failed", "reason": exc.code}
    return out


__all__ = ["add_create_flags", "add_verify_flags", "create_public", "refuse_keys", "verified"]
