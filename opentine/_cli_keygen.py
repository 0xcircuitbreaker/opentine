"""``tine keygen``: an Ed25519 keypair, or with ``--hmac`` a strong shared secret.

The private half goes to a file. It used to be printed whenever ``--out`` was
left off, and a seed on stdout is a seed in a CI log; printing it now takes an
explicit ``--stdout``. ``--hmac`` writes 32 random bytes as 64 hex characters --
the key ``--key-file`` / ``--key-env`` read -- because the 16-byte HMAC floor
alone let ``passwordpassword`` sign, and nothing made a good key.
"""

from __future__ import annotations

import argparse
import secrets
from pathlib import Path

from opentine._canon import atomic_write_text
from opentine._cli_common import _terminal, console
from opentine._cli_flags import refuse_unhonoured
from opentine.signing import SignatureError, generate_ed25519

HMAC_KEY_BYTES = 32


def _refuse(message: str) -> None:
    console.print(f"[red]{message}[/]")
    raise SystemExit(1)


def _refuse_flags(args: argparse.Namespace) -> None:
    if not args.out and not args.pub:
        # Keys printed to stdout replace no file, so --force would be accepted and
        # never consulted. Same shape as `sign --overwrite` without --save.
        refuse_unhonoured(
            args,
            ("force",),
            mode="without --out or --pub",
            hint="Keys printed to stdout replace no file; pass --out PATH to write one.",
        )
    if getattr(args, "hmac", False) and args.pub:
        _refuse("--pub has no effect with --hmac: an HMAC key is one shared secret.")
    if getattr(args, "stdout", False) and args.out:
        _refuse("--stdout and --out cannot be combined: the private key goes to one place.")
    if not args.out and not getattr(args, "stdout", False):
        _refuse(
            "Pass --out PATH to write the private key (mode 0600), or --stdout to print it; "
            "a key printed by default ends up in terminal scrollback and CI logs."
        )


def _claim(force: bool, *paths: str | None) -> None:
    """Refuse to replace an existing key without --force, or one file with both halves."""
    named = [path for path in paths if path]
    if len(named) == 2 and Path(named[0]) == Path(named[1]):
        # Writing the seed and then the public key to one path leaves only the
        # public key: the private half is destroyed and the command still exits 0.
        _refuse("--out and --pub must name different files.")
    # Silently overwriting a private key destroys the only copy of a signing
    # identity, and every artifact it signed becomes unverifiable.
    for existing in named:
        if Path(existing).exists() and not force:
            _refuse(f"{_terminal(existing)} already exists; pass --force.")


def cmd_keygen(args: argparse.Namespace) -> None:
    _refuse_flags(args)
    if getattr(args, "hmac", False):
        _claim(args.force, args.out)
        secret = secrets.token_hex(HMAC_KEY_BYTES)
        if args.out:
            atomic_write_text(args.out, secret + "\n", fsync=True, mode=0o600)
            console.print(f"Wrote a {HMAC_KEY_BYTES}-byte HMAC key to {_terminal(args.out)}")
        else:
            console.print(f"hmac key (hex): {secret}")
        return
    try:
        seed, public = generate_ed25519()
    except SignatureError as exc:
        _refuse(_terminal(exc))
    target_pub = args.pub or (args.out + ".pub" if args.out else None)
    _claim(args.force, args.out, target_pub)
    if args.out:
        atomic_write_text(args.out, seed + "\n", fsync=True, mode=0o600)
    else:
        console.print(f"private (seed hex): {seed}")
    if target_pub:
        atomic_write_text(target_pub, public + "\n")
    else:
        console.print(f"public (hex): {public}")


__all__ = ["HMAC_KEY_BYTES", "cmd_keygen"]
