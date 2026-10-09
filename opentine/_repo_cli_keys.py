"""Key material for the v3 attestation verbs, loaded the way ``tine sign`` loads it.

Two halves, deliberately spelled with the same flags as the legacy artifact
commands so one workflow does not need two vocabularies:

* ``signing_key`` is ``tine sign``'s half — ``--key-env`` / ``--key-file`` for the
  shared HMAC secret, ``--ed25519-key-file`` for a private key — used by
  ``tine attest`` and ``tine evaluate``. The algorithm is *inferred* from which
  flag was given rather than taken from a separate ``--algorithm``: an
  Ed25519 private key and an HMAC secret are not interchangeable, so a flag
  naming the key already names the algorithm.
* ``verification_keys`` is ``tine verify``'s half — ``--key-env`` / ``--key-file``
  for HMAC, ``--pubkey`` for a trusted Ed25519 public key,
  ``--trust-embedded-key`` for the block's own key (TOFU) — used by
  ``tine repo-verify``.

Both refuse *two* key flags rather than picking one. On the verify side that is
the ``KEY_MATERIAL_FLAGS`` rule ``tine verify`` already enforces: whichever key
the signature's own ``alg`` selects would win, so the object under inspection
gets to choose which of the operator's keys is trusted. On the signing side two
keys would mean the flag order silently decided who signed.

Every refusal here is raised, not printed: ``repo_cli.cmd_repo`` turns it into
the one ``tine <verb>: <message>`` line on **stderr** that every v3 verb refuses
with, leaving stdout empty so a ``--json`` consumer never has to parse a
refusal. That is also why this does not call ``_cli_flags.refuse_conflict``,
which prints on stdout for the legacy artifact verbs — it borrows only that
module's ``given``, so "was this flag supplied?" still has one definition.
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine._cli_flags import KEY_MATERIAL_FLAGS, given
from opentine._signing_keys import (
    SignatureError,
    ed25519_private_from_file,
    ed25519_public_from_file,
    hmac_key_from_env,
    hmac_key_from_file,
)

#: The three flags that can hand ``tine attest`` a *private* signing key.
SIGNING_KEY_FLAGS = ("key_env", "key_file", "ed25519_key_file")


def _refuse_two_keys(args: argparse.Namespace, dests: tuple[str, ...], hint: str) -> None:
    flags = given(args, dests)
    if len(flags) > 1:
        raise ValueError(f"{' and '.join(flags)} cannot be combined: only one takes effect. {hint}")


def _unreadable(exc: Exception) -> SignatureError:
    return SignatureError(f"cannot read the key: {exc}")


def signing_requested(args: argparse.Namespace) -> bool:
    return any(getattr(args, dest, None) for dest in SIGNING_KEY_FLAGS)


def signing_key(args: argparse.Namespace) -> tuple[Any | None, str]:
    """Return ``(key, algorithm)`` for the write verbs; ``(None, …)`` when unsigned."""
    _refuse_two_keys(
        args,
        SIGNING_KEY_FLAGS,
        "One attestation is signed with one key; pass the one you mean.",
    )
    if not signing_requested(args):
        return None, "hmac-sha256"
    try:
        if getattr(args, "ed25519_key_file", None):
            return ed25519_private_from_file(args.ed25519_key_file), "ed25519"
        if getattr(args, "key_env", None):
            return hmac_key_from_env(args.key_env), "hmac-sha256"
        return hmac_key_from_file(args.key_file), "hmac-sha256"
    except (OSError, SignatureError) as exc:
        raise _unreadable(exc) from exc


def verification_armed(args: argparse.Namespace) -> bool:
    """Whether anything arms the fail-closed check, as ``tine verify`` decides it.

    ``--trust-embedded-key`` and ``--require-signature`` are themselves requests
    to check authenticity, so they arm it exactly as a supplied key does.
    """
    return bool(
        getattr(args, "key_env", None)
        or getattr(args, "key_file", None)
        or getattr(args, "pubkey", None)
        or getattr(args, "trust_embedded_key", False)
        or getattr(args, "require_signature", False)
    )


def verification_keys(args: argparse.Namespace) -> dict[str, Any]:
    """Return the ``verify_attestation`` keyword arguments the flags name."""
    _refuse_two_keys(
        args,
        KEY_MATERIAL_FLAGS,
        "One signature is checked against one key, and the attestation would pick which.",
    )
    try:
        hmac_key = hmac_key_from_env(args.key_env) if getattr(args, "key_env", None) else None
        if getattr(args, "key_file", None):
            hmac_key = hmac_key_from_file(args.key_file)
        public = ed25519_public_from_file(args.pubkey) if getattr(args, "pubkey", None) else None
    except (OSError, SignatureError) as exc:
        raise _unreadable(exc) from exc
    return {
        "hmac_key": hmac_key,
        "public_key": public,
        "trust_embedded": bool(getattr(args, "trust_embedded_key", False)),
    }


__all__ = [
    "SIGNING_KEY_FLAGS",
    "signing_key",
    "signing_requested",
    "verification_armed",
    "verification_keys",
]
