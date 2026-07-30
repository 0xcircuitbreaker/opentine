"""Refuse flags the chosen mode cannot honour instead of dropping them.

argparse advertises every flag a subcommand declares, but several subcommands
branch into modes that read only a subset: `tine run` wires the autosave and
harness flags only in its ``--harness`` branch, `tine fork` builds a harness
only with ``--prompt``, and `tine replay --inspect` just lists recorded steps.
A flag the active mode cannot honour has to be refused out loud.  Exiting 0
after writing the artifact somewhere other than the requested ``--save`` path
is a lie the user only discovers by listing the directory.

"Was this flag given?" is decided by comparing the parsed value against the
parser default, so a flag left alone never triggers a refusal.  The defaults
below mirror ``_cli_parser``; a regression test compares the two table by table
for every subcommand that declares the flag, so drift fails the suite instead
of silently turning "given" into "not given".
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable

# dest -> (option string, parser default)
FLAG_DEFAULTS: dict[str, tuple[str, object]] = {
    "autosave": ("--autosave", None),
    "autosave_interval": ("--autosave-interval", 0),
    "autosave_seconds": ("--autosave-seconds", 0.0),
    "compare": ("--compare", False),
    "cwd": ("--cwd", None),
    "ed25519_key_file": ("--ed25519-key-file", None),
    "force": ("--force", False),
    "harness": ("--harness", None),
    "harness_arg": ("--harness-arg", []),
    "harness_command": ("--harness-command", None),
    "harness_env": ("--harness-env", []),
    "harness_login_env": ("--harness-login-env", False),
    "harness_max_events": ("--harness-max-events", 10_000),
    "harness_max_line_bytes": ("--harness-max-line-bytes", 1_000_000),
    "harness_max_output": ("--harness-max-output", 4_000_000),
    "harness_timeout": ("--harness-timeout", 3_600.0),
    "in_place": ("--in-place", False),
    "key_env": ("--key-env", None),
    "key_file": ("--key-file", None),
    "mode": ("--mode", "cache"),
    "out": ("--out", None),
    "overwrite": ("--overwrite", False),
    "prompt": ("--prompt", None),
    "pub": ("--pub", None),
    "pubkey": ("--pubkey", None),
    "save": ("--save", None),
    "trust_embedded_key": ("--trust-embedded-key", False),
}

AUTOSAVE_FLAGS = ("autosave", "autosave_interval", "autosave_seconds")

# Harness *configuration*: read only where a harness is actually constructed
# (``_cli_common._harness_from_args``), so meaningless in every other mode.
HARNESS_CONFIG_FLAGS = (
    "cwd",
    "harness_arg",
    "harness_command",
    "harness_env",
    "harness_login_env",
    "harness_max_events",
    "harness_max_line_bytes",
    "harness_max_output",
    "harness_timeout",
)

# Signature *key material*: ``verify_artifact`` consults exactly one of these, and
# the artifact under inspection picks which one — its ``alg`` selects the HMAC or
# the Ed25519 half, and --pubkey outranks --trust-embedded-key inside that half.
# Passing two therefore lets the file being checked decide which of the operator's
# keys is trusted, so a downgraded re-signing verifies against the weaker key.
KEY_MATERIAL_FLAGS = ("key_env", "key_file", "pubkey", "trust_embedded_key")


def given(args: argparse.Namespace, dests: Iterable[str]) -> list[str]:
    """Option strings among *dests* the user supplied (value differs from default)."""
    supplied = []
    for dest in dests:
        flag, default = FLAG_DEFAULTS[dest]
        if getattr(args, dest, default) != default:
            supplied.append(flag)
    return sorted(supplied)


def refuse_unhonoured(
    args: argparse.Namespace, dests: Iterable[str], *, mode: str, hint: str
) -> None:
    """Exit 1 naming the flags *mode* would otherwise ignore in silence."""
    flags = given(args, dests)
    if not flags:
        return
    from opentine._cli_common import console

    verb = "has" if len(flags) == 1 else "have"
    console.print(f"[red]{', '.join(flags)} {verb} no effect {mode}. {hint}[/]")
    raise SystemExit(1)


def refuse_conflict(args: argparse.Namespace, dests: Iterable[str], *, hint: str) -> None:
    """Exit 1 when two flags compete for one slot, so only one could be honoured.

    ``refuse_unhonoured`` names the mode that drops a flag; this names the pair
    where precedence alone decides the loser.  ``tine sign`` preferred --key-env
    over --key-file while ``tine verify`` preferred the opposite, so the same two
    flags meant different keys in the two halves of one workflow — silently.
    """
    flags = given(args, dests)
    if len(flags) < 2:
        return
    from opentine._cli_common import console

    console.print(
        f"[red]{' and '.join(flags)} cannot be combined: only one takes effect. {hint}[/]"
    )
    raise SystemExit(1)
