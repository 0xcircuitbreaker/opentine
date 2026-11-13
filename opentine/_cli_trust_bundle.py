"""``tine trust bundle create|verify`` (0.51): owner-signed browser trust bundles.

``create --key KEY --name NAME --serial N [--policy NAME | --pin FP...]
[--witnesses FILE] [--log-vkey V]... [--admission NAME=FILE]... [--expires T]
[--out FILE]`` signs a bundle (``_trust_bundle``) from existing documents: a
named trust policy's portable fields or ``--pin`` fingerprints, an
``opentine-witness-network/1`` registry, signed-note log keys and
``opentine.admission-policy`` files. ``verify FILE --owner-vkey V
[--min-serial N]`` checks one against the owner key pinned out of band and
exits 4 when it does not hold. Both take ``--json`` (``tine-cli-trust-bundle/1``).
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import VERIFICATION_FAILED, fail

__all__ = ["add_bundle_parser", "cmd_trust_bundle"]

SCHEMA = "tine-cli-trust-bundle/1"


def add_bundle_parser(group_sub: argparse._SubParsersAction) -> None:
    text = "Owner-signed trust bundles a browser viewer pins (0.51)"
    bundle = group_sub.add_parser("bundle", help=text, description=text)
    bundle.set_defaults(group_handler=cmd_trust_bundle)
    sub = bundle.add_subparsers(dest="bundle_command", metavar="SUBCOMMAND")
    create = sub.add_parser("create", help="Sign a trust bundle from existing trust documents")
    create.add_argument("--key", required=True, metavar="KEY", help="Owner Ed25519 key file")
    create.add_argument("--name", required=True, help="Owner key name (e.g. example.com/trust)")
    create.add_argument("--serial", required=True, type=int, help="Bundle serial (increases)")
    create.add_argument("--policy", dest="bundle_policy", metavar="NAME",
                        help="Take the portable fields of this named trust policy")  # fmt: skip
    create.add_argument("--pin", action="append", metavar="SHA256",
                        help="Pinned signer key fingerprint (repeatable)")  # fmt: skip
    create.add_argument("--witnesses", metavar="FILE", help="opentine-witness-network/1 file")
    create.add_argument("--log-vkey", action="append", help="Pinned log key")
    create.add_argument("--admission", action="append", metavar="NAME=FILE",
                        help="opentine.admission-policy document (repeatable)")  # fmt: skip
    create.add_argument("--expires", metavar="TIME", help="RFC 3339 expiry time")
    create.add_argument("--out", metavar="FILE", help="Write the bundle here (else stdout)")
    create.add_argument("--json", action="store_true", help="Emit a JSON object instead")
    check = sub.add_parser("verify", help="Check a trust bundle against the pinned owner key")
    check.add_argument("bundle", metavar="FILE", help="Trust bundle file")
    check.add_argument("--owner-vkey", required=True, help="Owner verifier key (name+hash+key)")
    check.add_argument("--min-serial", type=int, default=0, help="Refuse older serials")
    check.add_argument("--json", action="store_true", help="Emit a JSON object instead")


def _read(path: str) -> bytes:
    from opentine._trust_bundle import MAX_BYTES

    with open(path, "rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{path} exceeds {MAX_BYTES} bytes")
    return data


def _policy(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._signing_pins import normalize_pins
    from opentine._trust_bundle import PORTABLE, BundleError
    from opentine._trust_policy import load

    policy: dict[str, Any] = {}
    if args.bundle_policy:
        found = load()["policies"].get(args.bundle_policy)
        if found is None:
            raise BundleError(f"no trust policy named {args.bundle_policy!r}")
        local = sorted(set(found) - set(PORTABLE))
        if local:
            raise BundleError(f"policy {args.bundle_policy!r} names local files: {local}")
        policy = dict(found)
    if args.pin:
        policy["pin"] = sorted(set(policy.get("pin", [])) | normalize_pins(args.pin))
    return policy


def _payload(args: argparse.Namespace) -> dict[str, Any]:
    stamp = datetime.now(UTC).replace(microsecond=0)
    payload: dict[str, Any] = {
        "trust_bundle": 1,
        "serial": args.serial,
        "issued_at": stamp.isoformat().replace("+00:00", "Z"),
        "trust_policy": _policy(args),
    }
    if args.expires:
        payload["expires_at"] = args.expires
    if args.witnesses:
        payload["witness_network"] = json.loads(_read(args.witnesses))
    if args.log_vkey:
        payload["log_keys"] = list(args.log_vkey)
    if args.admission:
        policies = {}
        for spec in args.admission:
            name, sep, path = spec.partition("=")
            if not sep:
                raise ValueError(f"--admission {spec!r} is not NAME=FILE")
            policies[name] = json.loads(_read(path))
        payload["admission_policies"] = policies
    return payload


def summary(command: str, note: bytes, payload: dict[str, Any], owner: str) -> dict[str, Any]:
    from opentine._trust_bundle import digest

    out: dict[str, Any] = {
        "command": command,
        "schema": SCHEMA,
        "ok": True,
        "owner_vkey": owner,
        "digest": digest(note),
        "serial": payload["serial"],
        "issued_at": payload["issued_at"],
        "pins": sorted(payload["trust_policy"].get("pin", [])),
        "log_keys": list(payload.get("log_keys", [])),
        "admission_policies": sorted(payload.get("admission_policies", {})),
    }
    if "expires_at" in payload:
        out["expires_at"] = payload["expires_at"]
    if "witness_network" in payload:
        network = payload["witness_network"]
        out["witness_network"] = {"log": network["log"]["origin"],
                                  "quorum": network["policy"]["quorum"]}  # fmt: skip
    return out


def _create(args: argparse.Namespace) -> None:
    from opentine import _trust_bundle
    from opentine._signing_keys import SignatureError, ed25519_private_from_file
    from opentine._trust_policy import PolicyError
    from opentine.repository._tlog_note import vkey_for

    try:
        key = ed25519_private_from_file(args.key)
        payload = _payload(args)
        note = _trust_bundle.sign(payload, key, args.name)
    except (OSError, SignatureError, PolicyError, ValueError) as exc:
        fail(exc, prefix="trust bundle: ", cause=exc)
    owner = vkey_for(args.name, key.public_key().public_bytes_raw())
    if args.out:
        Path(args.out).write_bytes(note)
    if args.json:
        from opentine._cli_json import emit

        result = summary("trust bundle create", note, payload, owner)
        emit({**result, "path": args.out} if args.out else result)
    elif args.out:
        console.print(f"trust bundle serial {payload['serial']} written to {_terminal(args.out)}")
        console.print(f"owner key to pin: {owner}", highlight=False)
    else:
        print(note.decode("utf-8"), end="")


def _verify(args: argparse.Namespace) -> None:
    from opentine import _trust_bundle

    try:
        note = _read(args.bundle)
    except (OSError, ValueError) as exc:
        fail(exc, prefix="trust bundle: ", cause=exc)
    try:
        payload = _trust_bundle.open_bundle(note, args.owner_vkey, min_serial=args.min_serial)
    except _trust_bundle.BundleError as exc:
        fail(exc, VERIFICATION_FAILED, prefix="trust bundle: ", cause=exc)
    result = summary("trust bundle verify", note, payload, args.owner_vkey.strip())
    if args.json:
        from opentine._cli_json import emit

        emit(result)
        return
    console.print(
        f"trust bundle verified: serial {result['serial']}, {len(result['pins'])} pinned "
        f"signer(s), {len(result['log_keys'])} log key(s), {result['digest']}",
        highlight=False,
    )


def cmd_trust_bundle(args: argparse.Namespace) -> None:
    command = getattr(args, "bundle_command", None)
    if command is None:
        from opentine._cli_groups import cmd_group

        return cmd_group(args)
    return _create(args) if command == "create" else _verify(args)
