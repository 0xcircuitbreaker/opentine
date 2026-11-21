"""The keyless assurance tier ``tine verify`` shows beside a certificate check (0.75).

A keyless signature that verifies proves only that *some* identity Fulcio
vouched for signed. ``tine verify --offline --attestation`` names that
identity's tier (:func:`opentine._keyless_identity.tier`) and reports it as a
caveat (``caveat:keyless-unpinned``, not trusted) unless the owner-pinned trust
bundle's ``trust_policy`` names the exact issuer and identity. A missing,
unreadable or rolled-back bundle pins nothing, so the result stays a caveat:
this never raises and never trusts by default. The caller's
``--certificate-identity`` flags still gate the chain check; they are not an
owner pin.
"""

from __future__ import annotations

from typing import Any

UNPINNED = "caveat:keyless-unpinned"


def owner_pins() -> list[dict[str, str]]:
    """The owner-pinned keyless identities; none without a pinned owner or a good bundle."""
    from pathlib import Path

    from opentine._key_roles_pin import _serials, bundle_path, owner_vkey
    from opentine._trust_bundle import BundleError, open_bundle

    owner = owner_vkey()
    if owner is None:
        return []
    try:
        raw = bundle_path(Path(".tine")).read_bytes()
        payload = open_bundle(raw, owner, min_serial=_serials().get(owner, 0))
    except (OSError, BundleError, ValueError):
        return []
    policy = payload.get("trust_policy")
    return [policy] if isinstance(policy, dict) else []


def assess(material: Any) -> dict[str, Any]:
    """``{"tier", "pinned", "code"}`` for the bundle's leaf; unreadable: unbound, unpinned."""
    from opentine._fulcio_verify import leaf_from_material
    from opentine._keyless_identity import facts, pinned_by, tier

    try:
        leaf = leaf_from_material(material)
        identity = facts(leaf) if leaf is not None else None
    except (ValueError, TypeError):
        identity = None
    if identity is None:
        return {"tier": "keyless-unbound", "pinned": False, "code": UNPINNED}
    pinned = pinned_by(identity, owner_pins()) is not None
    code = "keyless.trusted" if pinned else UNPINNED
    return {"tier": tier(identity), "pinned": pinned, "code": code}


def detail(found: dict[str, Any]) -> str:
    if found["pinned"]:
        return f"chain and identity; tier {found['tier']}; pinned by the owner's trust bundle"
    return (f"chain and identity; tier {found['tier']}; {UNPINNED}: no owner-pinned trust "
            "bundle entry names this issuer and identity, so it is not trusted")  # fmt: skip


__all__ = ["UNPINNED", "assess", "detail", "owner_pins"]
