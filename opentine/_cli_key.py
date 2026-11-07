"""``tine key``: signing keys at rest, the signers behind them, and their lifecycle (0.41).

* ``tine key encrypt PATH`` rewrites a 0.40-and-earlier plaintext-hex private
  key as encrypted PKCS#8 (passphrase from ``OPENTINE_KEY_PASSPHRASE``, the OS
  keyring or a prompt). An already encrypted key is left alone (X24).
* ``tine key show SIGNER`` opens a signer URI (``file:``, ``ssh-agent:``,
  ``pkcs11:``, ``kms:``) and prints its algorithm, key id and public key -- the
  values to pin in ``agents.toml`` or hand to a verifier.
* ``tine key rotate KEY [--out NEW]`` / ``--agent NAME`` / ``--proxy``: a new
  Ed25519 key, written encrypted, replaces *KEY*; the old key gets
  ``not_after = now`` and endorses the new one (``_key_rotate``, X23). A rotated
  proxy key is retired the way ``tine proxy migrate`` retires it, so runs it
  witnessed stay T2.
* ``tine key revoke KEY [--at TIME]``: ``revoked_at`` (default now) for a
  fingerprint, a ``.pub`` file or a private key file.

Rotate and revoke write ``$XDG_CONFIG_HOME/opentine/key-lifecycle.json``; ``tine
verify`` reads it (``_key_lifecycle_verify``).
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._cli_errors import ERROR, NOT_FOUND, USAGE, fail


def add_key_parser(sub: Any) -> None:
    key = sub.add_parser("key", help="Encrypt, inspect, rotate or revoke signing keys")
    verbs = key.add_subparsers(dest="key_command")
    encrypt = verbs.add_parser("encrypt", help="Rewrite a plaintext-hex key as encrypted PKCS#8")
    encrypt.add_argument("path", metavar="PATH")
    encrypt.add_argument("--json", action="store_true", help="Print a JSON object")
    show = verbs.add_parser("show", help="Print a signer's key id and public key")
    show.add_argument("signer", metavar="SIGNER", help="file:PATH, ssh-agent:FPR, pkcs11:..., kms:")
    show.add_argument("--json", action="store_true", help="Print a JSON object")
    rotate = verbs.add_parser("rotate", help="Replace a key; the old one endorses the new")
    rotate.add_argument("key", nargs="?", metavar="KEY", help="Ed25519 private key file")
    rotate.add_argument("--out", metavar="NEW", help="Write the new key here; keep KEY as is")
    rotate.add_argument("--agent", metavar="NAME", help="Rotate the agent key from keygen --agent")
    rotate.add_argument("--proxy", action="store_true", help="Rotate the proxy witness key")
    rotate.add_argument("--json", action="store_true", help="Print a JSON object")
    revoke = verbs.add_parser("revoke", help="Mark a key revoked from a time on")
    revoke.add_argument("key", metavar="KEY", help="sha256:<hex>, a .pub file or a key file")
    revoke.add_argument("--at", metavar="TIME", help="RFC 3339 revocation time (default: now)")
    revoke.add_argument("--json", action="store_true", help="Print a JSON object")


def _rotate_paths(args: argparse.Namespace) -> tuple[Path, Path | None, Path | None]:
    chosen = [bool(args.key), bool(args.agent), bool(args.proxy)]
    if sum(chosen) != 1:
        fail("name one key: KEY, --agent NAME or --proxy", USAGE)
    retired_dir = None
    if args.agent or args.proxy:
        if args.out:
            fail("--out applies to a KEY file; --agent and --proxy keys stay in place", USAGE)
        if args.proxy:
            from opentine import _proxy_key

            if _proxy_key.signer_path().exists():
                fail("the proxy key is held by a signer; use tine proxy migrate --to URI", USAGE)
            key_paths = _proxy_key.key_paths
            retired_dir = _proxy_key.base() / "retired"
        else:
            from opentine._agent_keys import key_paths as agent_paths

            key_paths = lambda: agent_paths(args.agent)  # noqa: E731
        try:
            private, public = key_paths()
        except ValueError as exc:
            fail(exc, USAGE)
    else:
        private = Path(args.key)
        public = Path(f"{private}.pub")
    if not private.is_file():
        fail(f"no private key at {private}", NOT_FOUND)
    return private, public, retired_dir


def _lifecycle(args: argparse.Namespace, verb: str) -> None:
    from opentine import _key_rotate
    from opentine._cli_common import _terminal, console
    from opentine._cli_json import emit
    from opentine._key_store import PassphraseUnavailable
    from opentine.signing import SignatureError

    out = None
    try:
        if verb == "rotate":
            private, public, retired_dir = _rotate_paths(args)
            out = Path(args.out) if args.out else None
            result = _key_rotate.rotate(private, public, out, retired_dir=retired_dir)
        else:
            result = _key_rotate.revoke(args.key, args.at)
    except (OSError, PassphraseUnavailable, SignatureError, ValueError) as exc:
        fail(exc, USAGE if "--at" in str(exc) else 1, prefix=f"key {verb}: ", cause=exc)
    if getattr(args, "json", False):
        emit({"command": f"key {verb}", **result})
    elif verb == "rotate":
        console.print(f"rotated {result['old']} -> {result['new']}", highlight=False)
        console.print(
            f"old key not_after {result['not_after']}; new key {_terminal(out or private)}"
        )
    else:
        console.print(f"revoked {result['key']} at {result['revoked_at']}", highlight=False)


def cmd_key(args: argparse.Namespace) -> None:
    from opentine._cli_common import _terminal, console
    from opentine._cli_json import emit
    from opentine._key_store import PassphraseUnavailable, encrypt_file
    from opentine._signer import resolve
    from opentine._signing_keys import SignatureError

    verb = getattr(args, "key_command", None)
    if verb in ("rotate", "revoke"):
        _lifecycle(args, verb)
        return
    if verb not in ("encrypt", "show"):
        fail("name a key command: tine key encrypt|show|rotate|revoke", USAGE)
    prefix = f"key {verb}: "
    if verb == "encrypt":
        if not Path(args.path).is_file():
            fail(f"no key file at {args.path}", NOT_FOUND, prefix=prefix)
        try:
            changed = encrypt_file(args.path)
        except (OSError, PassphraseUnavailable, SignatureError, ValueError) as exc:
            fail(exc, ERROR, prefix=prefix)
        if getattr(args, "json", False):
            emit({"command": "key encrypt", "path": str(args.path), "changed": changed})
            return
        state = "Encrypted" if changed else "Already encrypted:"
        console.print(f"{state} {_terminal(args.path)}")
        return
    try:
        found = resolve(args.signer)
        public = bytes(found.public_key).hex()
    except (OSError, SignatureError, ValueError) as exc:
        fail(exc, ERROR, prefix=prefix)
    row = {
        "command": "key show",
        "signer": found.uri or args.signer,
        "algorithm": found.algorithm,
        "key_id": found.key_id,
        "public_key": public,
    }
    if getattr(args, "json", False):
        emit(row)
        return
    for name in ("signer", "algorithm", "key_id", "public_key"):
        console.print(f"{name:<10} {_terminal(row[name])}")


COMMANDS = {"key": cmd_key}

__all__ = ["COMMANDS", "add_key_parser", "cmd_key"]
