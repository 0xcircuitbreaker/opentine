"""Where ``tine verify`` applies key lifecycle (X23, ``_key_lifecycle``).

* ``tine verify RUN --offline`` adds a ``key-lifecycle`` check after the
  timestamp checks, judged against the report's verified ``signing_time``.
* plain ``tine verify RUN --pubkey/--pin`` has no verified time, so it refuses
  (exit 4) a revoked key or a claimed time outside the window, and otherwise
  says the window was checked against an unverified time.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._verify_report import Check

NAME = "key-lifecycle"


def sources(args: argparse.Namespace) -> tuple[dict, ...]:
    """Registry, trusted agents.toml and trust-policy lifecycle tables."""
    from opentine import _cli_who_trust as who_trust
    from opentine._key_lifecycle import agent_lifecycle, check_table, load_registry

    try:
        _, _, agents = who_trust.scope_paths(args)
    except (OSError, ValueError, AttributeError, SystemExit):
        agents = None
    policy = getattr(args, "key_lifecycle", None)
    return load_registry(), agent_lifecycle(agents), check_table(policy) if policy else {}


def signer(args: argparse.Namespace, path: Path) -> tuple[str | None, str | None]:
    """``(fingerprint, claimed signed_at)`` of the key the signature verdict rests on."""
    from opentine._cli_verify_report import read_once, signature_block
    from opentine._signing_pins import used_key_fingerprint
    from opentine.signing import ed25519_public_from_file

    pubkey = getattr(args, "pubkey", None)
    block = signature_block(read_once(path))
    fpr = used_key_fingerprint(block, ed25519_public_from_file(pubkey) if pubkey else None)
    claimed = block.get("signed_at") if isinstance(block, dict) else None
    return fpr, claimed if isinstance(claimed, str) else None


def lifecycle_check(
    args: argparse.Namespace, path: Path, signature: Check, verified: str | None
) -> Check | None:
    """The ``key-lifecycle`` check, or ``None`` when no window names the signer."""
    from opentine._key_lifecycle import evaluate, lifecycle_for

    if signature.outcome != "pass":
        return None
    try:
        fpr, claimed = signer(args, path)
        window = lifecycle_for(fpr, *sources(args))
    except (OSError, ValueError) as exc:
        return Check(NAME, "fail", "lifecycle.unreadable", str(exc), "none", required=True)
    if window is None:
        return None
    outcome, reason, detail = evaluate(window, verified, claimed)
    basis = f"lifecycle of {fpr} at the {'verified' if verified else 'unverified'} signing time"
    return Check(NAME, outcome, reason, detail, basis, required=outcome == "fail")


def refuse_out_of_window(fpr: str | None, claimed: str | None, args: Any = None) -> str | None:
    """Plain verify: exit 4 on a lifecycle failure; returns a note for the OK line."""
    from opentine._cli_errors import VERIFICATION_FAILED, fail
    from opentine._key_lifecycle import evaluate, lifecycle_for

    try:
        window = lifecycle_for(fpr, *sources(args or argparse.Namespace()))
    except (OSError, ValueError) as exc:
        fail(f"KEY LIFECYCLE unreadable: {exc}", VERIFICATION_FAILED)
    if window is None:
        return None
    outcome, reason, detail = evaluate(window, None, claimed)
    if outcome == "fail":
        fail(f"KEY LIFECYCLE FAILED {reason}: {detail}", VERIFICATION_FAILED)
    return "key window checked against an unverified time (use --offline with a timestamp)"


__all__ = ["NAME", "lifecycle_check", "refuse_out_of_window", "signer", "sources"]
