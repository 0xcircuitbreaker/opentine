"""Who may sign the evals that justify a lineage variant (0.58).

``tine lineage check`` proves who signed each verdict; this module says whether
that signer is *trusted*. The trust comes from the 0.57 key separation: the
repository's ``.tine/key-roles.toml`` ``scorer`` role (:mod:`opentine._key_roles`,
read through :func:`opentine._promote_pins.roles`) and, when given, the
promotion policy's ``eval_signers`` pin (:func:`opentine._promote_checks.load_policy`).
When both are present a signer must be in both. A key in the ``optimizer`` role
is never trusted, so a loop cannot sign its own evals and record them.

The trust is a plain ``{"eval_signers": [...], "optimizer": [...]}`` mapping, so
the TS port and the shared fixture carry it as data. With neither source the
check reports ``signers: "unpinned"`` (a warning, not a pass claim on who
signed); with one it reports ``"pinned"`` and refuses an untrusted verdict
signer with ``lineage.signer-untrusted``.
"""

from __future__ import annotations

from pathlib import Path

UNPINNED_WARNING = ("eval signers are unpinned: no .tine/key-roles.toml scorer role or "
                    "promotion policy eval_signers, so a verdict's signer is proven, "
                    "not trusted")  # fmt: skip


def load_trust(repo_path: Path | None, promotion_policy: Path | None = None) -> dict | None:
    """The trust mapping for a repository, or ``None`` when signers are unpinned."""
    from opentine._promote_checks import load_policy
    from opentine._promote_pins import roles

    held = roles(repo_path) or {}
    scorer = set(held.get("scorer", []))
    pinned = set(load_policy(promotion_policy)["eval_signers"]) if promotion_policy else set()
    if not scorer and not pinned:
        return None
    allowed = scorer & pinned if scorer and pinned else scorer | pinned
    return {"eval_signers": sorted(allowed), "optimizer": sorted(held.get("optimizer", []))}


def status(trust: dict | None) -> str:
    return "unpinned" if trust is None else "pinned"


def untrusted(signers: set[str], trust: dict | None) -> str | None:
    """Why some verdict signer is not trusted, or ``None``."""
    if trust is None:
        return None
    allowed, optimizer = set(trust["eval_signers"]), set(trust["optimizer"])
    bad = sorted(s for s in signers if s not in allowed or s in optimizer)
    if not bad:
        return None
    return (f"verdicts signed by {', '.join(bad)}: not an allowed eval-signer key, "
            "or an optimizer key")  # fmt: skip


__all__ = ["UNPINNED_WARNING", "load_trust", "status", "untrusted"]
