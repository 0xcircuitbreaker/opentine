"""``tine actions RUN --sign`` / ``--verify`` and ``tine audit --require-signed``.

Signing writes a ``tine-actions/1`` manifest (``_actions_manifest``) beside the
runs -- ``<runs dir>/manifests/`` or ``.tine/actions/`` in a repository --
named by a hash of the run id. Keys come from the same flags ``tine sign`` and
``tine attest`` use, or ``--agent NAME`` for a key made by
``tine keygen --agent NAME``. Verification recomputes the manifest from the
run, so it reports a trust state, never a stored one.
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine import _actions_manifest as manifest_mod
from opentine import _cli_who_trust as who_trust
from opentine._actions_verdict import Trust, load_manifest, save_manifest, verify
from opentine._agent_identity import run_identity
from opentine._agent_keys import key_paths, trusted_fingerprints
from opentine._cli_common import _terminal, console
from opentine._signing_keys import SignatureError, ed25519_private_from_file
from opentine._signing_pins import key_fingerprint, normalize_pins


def _fail(message: str) -> None:
    console.print(f"[red]{_terminal(message)}[/]")
    raise SystemExit(2)


def _signing_key(args: argparse.Namespace) -> tuple[Any, str]:
    from opentine._repo_cli_keys import signing_key

    if getattr(args, "agent", None):
        if any(getattr(args, name, None) for name in ("key_env", "key_file", "ed25519_key_file")):
            raise ValueError("--agent and a key flag cannot be combined: pass one key")
        return ed25519_private_from_file(key_paths(args.agent)[0]), "ed25519"
    key, algorithm = signing_key(args)
    if key is None:
        raise ValueError("--sign needs a key: --agent NAME, --ed25519-key-file, or an HMAC key")
    return key, algorithm


def _sign(args: argparse.Namespace, run: Any, base: Any) -> None:
    try:
        key, algorithm = _signing_key(args)
        record = run_identity(run) or {}
        if record.get("key_fpr"):
            used = (
                key_fingerprint(key.public_key().public_bytes_raw())
                if algorithm == "ed25519"
                else None
            )
            if used != record["key_fpr"]:
                raise ValueError("this key is not the one the run's agent identity names")
        manifest = manifest_mod.sign(run, key, algorithm=algorithm, key_id=args.key_id)
        path = save_manifest(base, manifest)
    except (OSError, SignatureError, ValueError) as exc:
        _fail(f"Cannot sign actions: {exc}")
        return
    body = manifest["body"]
    console.print(
        f"Signed {len(body['entries'])} action(s) of {_terminal(run.id)} as "
        f"{_terminal(body['agent_ref'])} -> {_terminal(path)}"
    )


def _verify(args: argparse.Namespace, run: Any, base: Any, agents: Any) -> None:
    from opentine._cli_json import emit
    from opentine._repo_cli_keys import verification_keys

    try:
        keys = verification_keys(args)
        pins = normalize_pins(args.pin) | trusted_fingerprints(agents)
    except (SignatureError, ValueError) as exc:
        _fail(str(exc))
        return
    stored = load_manifest(base, run.id)
    if stored is False:
        trust = Trust("mismatch", "action manifest is unreadable")
    else:
        trust = verify(
            stored, run, hmac_key=keys["hmac_key"], public_key=keys["public_key"], pins=pins
        )
    if args.json:
        emit(
            {
                "command": "actions",
                "run_id": run.id,
                "trust": trust.state,
                "reason": trust.reason,
                "key": trust.key,
            }
        )
    else:
        color = "green" if trust.verified else "red"
        console.print(
            f"[{color}]{trust.state}[/] {_terminal(run.id)}: {_terminal(trust.reason)}"
            + (f" (key {_terminal(trust.key)})" if trust.key else "")
        )
    if not trust.verified:
        raise SystemExit(1)


def sign_or_verify(args: argparse.Namespace, run: Any) -> None:
    if args.sign and args.verify:
        _fail("--sign and --verify cannot be combined")
    try:
        _, base, agents = who_trust.scope_paths(args)
    except (OSError, ValueError) as exc:
        _fail(str(exc))
        return
    if args.sign:
        _sign(args, run, base)
    else:
        _verify(args, run, base, agents)


def require_signed(args: argparse.Namespace, index: Any) -> dict[str, Any]:
    """Every indexed run's trust state; with ``--require-signed``, the unverified ones."""
    try:
        trust = who_trust.resolver(args, index)
    except (OSError, ValueError) as exc:
        _fail(str(exc))
        raise
    states = {run_id: trust.trust(run_id).state for run_id in index.run_ids()}
    required = bool(getattr(args, "require_signed", False))
    unverified = sorted(r for r, s in states.items() if s != "verified") if required else []
    return {"required": required, "states": states, "unverified": unverified}


def add_sign_args(parser: argparse.ArgumentParser) -> None:
    from opentine._repo_cli_keys import add_key_args

    parser.add_argument(
        "--sign", action="store_true", help="Write a signed tine-actions/1 manifest"
    )
    parser.add_argument("--verify", action="store_true", help="Check the run's action manifest")
    parser.add_argument(
        "--agent", metavar="NAME", help="Sign with `tine keygen --agent NAME`'s key"
    )
    add_key_args(parser, signing=True)
    parser.add_argument("--pubkey", help="File holding a trusted Ed25519 public key")


__all__ = ["add_sign_args", "require_signed", "sign_or_verify"]
