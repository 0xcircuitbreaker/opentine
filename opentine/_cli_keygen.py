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


def _agent_paths(args: argparse.Namespace) -> None:
    """``--agent NAME``: the key goes to this user's agent-key directory, nowhere else."""
    from opentine._agent_keys import key_paths

    if args.out or args.pub or args.stdout or args.hmac:
        _refuse(
            "--agent cannot be combined with --out/--pub/--stdout/--hmac: it writes its own files."
        )
    try:
        private, public = key_paths(args.agent)
    except ValueError as exc:
        _refuse(_terminal(exc))
    private.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.out, args.pub = str(private), str(public)


def cmd_keygen(args: argparse.Namespace) -> None:
    if getattr(args, "agent", None):
        _agent_paths(args)
    _refuse_flags(args)
    if getattr(args, "hmac", False):
        _claim(args.force, args.out)
        secret = secrets.token_hex(HMAC_KEY_BYTES)
        if args.out:
            # newline="": key files are read as bytes minus one "\n", so a
            # Windows "\r\n" would make "\r" part of the key.
            atomic_write_text(args.out, secret + "\n", fsync=True, mode=0o600, newline="")
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


def add_keygen_parser(sub) -> None:
    keygen = sub.add_parser("keygen", help="Generate an Ed25519 keypair, or an HMAC key")
    keygen.add_argument("--out", help="Write the private key here (mode 0600)")
    keygen.add_argument("--pub")
    keygen.add_argument("--force", action="store_true", help="Overwrite an existing key file")
    keygen.add_argument("--hmac", action="store_true", help="A 32-byte HMAC key, as hex")
    keygen.add_argument("--stdout", action="store_true", help="Print the private key instead")
    keygen.add_argument(
        "--agent", metavar="NAME", help="An agent signing key, kept in the user config dir"
    )


__all__ = ["HMAC_KEY_BYTES", "add_keygen_parser", "cmd_keygen"]
