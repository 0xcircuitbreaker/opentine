"""Owner-pinned k floors for oversight tiers (0.64).

``.tine/oversight.toml`` is pinned by a policy-role signature, but an older,
validly signed copy (lower k) can be put back. When the owner-signed trust
bundle (:mod:`opentine._trust_bundle`, pinned outside the repository as in
:mod:`opentine._key_roles_pin`) carries
``"oversight": {"version": 1, "tiers": {NAME: {"k": N}}}``, each pinned tier's
k is a floor: the file may raise it but never lower it, and a pinned tier the
file lacks leaves the policy unpinned. A bad or rolled-back bundle under a
pinned owner is an :class:`~opentine._oversight_policy.OversightError` (the
gate refuses).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def tiers_of(doc: Any) -> dict[str, int] | None:
    """``{tier: k}`` of an ``oversight`` bundle section, or ``None`` if malformed."""
    if not isinstance(doc, dict) or doc.get("version") != 1 or set(doc) - {"version", "tiers"}:
        return None
    tiers = doc.get("tiers")
    if not isinstance(tiers, dict):
        return None
    out: dict[str, int] = {}
    for name, row in tiers.items():
        k = row.get("k") if isinstance(row, dict) else None
        if not isinstance(name, str) or type(k) is not int or k < 1 or set(row) != {"k"}:
            return None
        out[name] = k
    return dict(sorted(out.items()))


def pinned_tiers(store: Path) -> dict[str, int] | None:
    """Floors from a verified, owner-pinned bundle; ``None`` when none pins them."""
    from opentine._key_roles_pin import _serials, bundle_path, owner_vkey
    from opentine._oversight_policy import OversightError
    from opentine._trust_bundle import BundleError, open_bundle

    owner = owner_vkey()
    if owner is None:
        return None
    try:
        note = bundle_path(store).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise OversightError(f"trust bundle: {exc}") from exc
    try:
        payload = open_bundle(note, owner, min_serial=_serials().get(owner, 0))
    except BundleError as exc:
        raise OversightError(f"trust bundle: {exc}") from exc
    return tiers_of(payload["oversight"]) if "oversight" in payload else None


def apply(policy: dict[str, Any], floors: dict[str, int]) -> str:
    """Raise each pinned tier's k in *policy*; why it is unpinned, or ``""``."""
    missing = sorted(set(floors) - set(policy["tiers"]))
    if missing:
        return f"the trust bundle pins tier(s) {', '.join(missing)}, which the policy lacks"
    for name, k in floors.items():
        policy["tiers"][name]["k"] = max(policy["tiers"][name]["k"], k)
    return ""


__all__ = ["apply", "pinned_tiers", "tiers_of"]
