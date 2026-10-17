"""The bearer token a remote verb sends, read from the least visible source."""

from __future__ import annotations

import argparse
import os
import stat
import sys

from opentine._cli_common import _terminal

MAX_TOKEN_FILE_BYTES = 8192


def _token(args: argparse.Namespace) -> str | None:
    """The bearer token for a remote verb, from the least visible source given.

    ``--token`` puts the secret in argv, where ``ps``, ``/proc`` and shell
    history see it: it still works, with a warning. ``--token-file`` and
    ``TINE_REMOTE_TOKEN`` (read later when neither flag is given) do not.
    """
    token, path = args.token, getattr(args, "token_file", None)
    if token and path:
        raise ValueError("pass --token or --token-file, not both")
    if path:
        _warn_readable(path)
        with open(path, "rb") as handle:
            raw = handle.read(MAX_TOKEN_FILE_BYTES + 1)
        secret = raw.decode("utf-8", "strict").strip() if len(raw) <= MAX_TOKEN_FILE_BYTES else ""
        if not secret or any(character.isspace() for character in secret):
            raise ValueError("--token-file must hold exactly one token")
        return secret
    if token:
        sys.stderr.write(
            "warning: --token exposes the bearer token to the process list and shell "
            "history; set TINE_REMOTE_TOKEN or use --token-file instead\n"
        )
    return token


def _warn_readable(path: str) -> None:
    """ssh's rule for a secret file, as key files already get: owner-only."""
    if os.name != "posix":
        return
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return  # the read below reports it
    if mode & 0o077:
        sys.stderr.write(
            f"warning: token file {_terminal(path)} is readable by others "
            f"(mode {mode:04o}); run `chmod 600 {_terminal(path)}`\n"
        )
