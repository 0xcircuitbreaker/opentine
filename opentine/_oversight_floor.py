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

0.85: the section may also carry ``"routes": [SOURCE, ...]`` (each source must
keep at least one route in the file) and ``"policy_sha256": HEX`` (the file's
bytes must be exactly these). Putting back an older signed policy without the
``promotion`` route, or any other bytes than the pinned digest, leaves the
policy unpinned, and ``promote`` refuses (``promote.oversight-insufficient``)
even when nothing would be routed. ``tiers`` is optional once either is given.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

_FIELDS = {"version", "tiers", "routes", "policy_sha256"}


def section_of(doc: Any) -> dict[str, Any] | None:
    """``{"tiers", "routes", "policy_sha256"}`` of a bundle section, ``None`` if malformed."""
    import re

    from opentine._oversight_policy import SOURCES

    if not isinstance(doc, dict) or doc.get("version") != 1 or set(doc) - _FIELDS:
        return None
    if not set(doc) & {"tiers", "routes", "policy_sha256"}:
        return None
    tiers = tiers_of({"version": 1, "tiers": doc.get("tiers", {})})
    routes = doc.get("routes", [])
    digest = doc.get("policy_sha256")
    if tiers is None or not isinstance(routes, list) or not all(r in SOURCES for r in routes):
        return None
    if digest is not None and not (isinstance(digest, str) and re.fullmatch("[0-9a-f]{64}",
                                                                           digest)):  # fmt: skip
        return None
    return {"tiers": tiers, "routes": sorted(set(routes)), "policy_sha256": digest}


def tiers_of(doc: Any) -> dict[str, int] | None:
    """``{tier: k}`` of an ``oversight`` bundle section, or ``None`` if malformed."""
    if not isinstance(doc, dict) or doc.get("version") != 1 or set(doc) - _FIELDS:
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
    found = pinned(store)
    return found["tiers"] if found is not None else None


def pinned(store: Path) -> dict[str, Any] | None:
    """The verified, owner-pinned ``oversight`` section; ``None`` when none is pinned."""
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
    return section_of(payload["oversight"]) if "oversight" in payload else None


def apply(policy: dict[str, Any], floors: dict[str, Any]) -> str:
    """Raise each pinned tier's k in *policy*; why it is unpinned, or ``""``.

    *floors* is a :func:`section_of` row (or a bare ``{tier: k}`` as before 0.85).
    """
    if "tiers" in floors and isinstance(floors.get("routes"), list):
        digest, routes = floors["policy_sha256"], floors["routes"]
        if digest is not None and policy["sha256"] != digest:
            return f"the trust bundle pins policy sha256 {digest}; the file is {policy['sha256']}"
        lost = sorted(set(routes) - {r["source"] for r in policy["routes"]})
        if lost:
            return f"the trust bundle pins route(s) for {', '.join(lost)}, which the policy lacks"
        floors = floors["tiers"]
    missing = sorted(set(floors) - set(policy["tiers"]))
    if missing:
        return f"the trust bundle pins tier(s) {', '.join(missing)}, which the policy lacks"
    for name, k in floors.items():
        policy["tiers"][name]["k"] = max(policy["tiers"][name]["k"], k)
    return ""


__all__ = ["apply", "pinned", "pinned_tiers", "section_of", "tiers_of"]
