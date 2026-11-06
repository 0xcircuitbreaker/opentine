"""``tine key``: signing keys at rest and the signers behind them (0.41, X24).

* ``tine key encrypt PATH`` rewrites a 0.40-and-earlier plaintext-hex private
  key as encrypted PKCS#8 (passphrase from ``OPENTINE_KEY_PASSPHRASE``, the OS
  keyring or a prompt). An already encrypted key is left alone.
* ``tine key show SIGNER`` opens a signer URI (``file:``, ``ssh-agent:``,
  ``pkcs11:``, ``kms:``) and prints its algorithm, key id and public key -- the
  values to pin in ``agents.toml`` or hand to a verifier.
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine._cli_errors import ERROR, NOT_FOUND, USAGE, fail


def add_key_parser(sub: Any) -> None:
    key = sub.add_parser("key", help="Encrypt signing keys and inspect signers")
    verbs = key.add_subparsers(dest="key_command")
    encrypt = verbs.add_parser("encrypt", help="Rewrite a plaintext-hex key as encrypted PKCS#8")
    encrypt.add_argument("path", metavar="PATH")
    encrypt.add_argument("--json", action="store_true", help="Print a JSON object")
    show = verbs.add_parser("show", help="Print a signer's key id and public key")
    show.add_argument("signer", metavar="SIGNER", help="file:PATH, ssh-agent:FPR, pkcs11:..., kms:")
    show.add_argument("--json", action="store_true", help="Print a JSON object")


def cmd_key(args: argparse.Namespace) -> None:
    from pathlib import Path

    from opentine._cli_common import _terminal, console
    from opentine._cli_json import emit
    from opentine._key_store import PassphraseUnavailable, encrypt_file
    from opentine._signer import resolve
    from opentine._signing_keys import SignatureError

    verb = getattr(args, "key_command", None)
    if verb not in ("encrypt", "show"):
        fail("name a key command: tine key encrypt PATH | tine key show SIGNER", USAGE)
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
