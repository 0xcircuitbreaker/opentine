"""Which key may speak for which monitor (0.90): the trust bundle's ``monitors`` section.

A pinned ``monitor`` key proves a record came from *a* monitor, not from the
monitor it names. The owner-signed trust bundle (:mod:`opentine._trust_bundle`)
binds each monitor id to its signer fingerprints and may name the monitors a
promotion requires::

    "monitors": {"version": 1,
                 "signers": {"MONITOR-ID": ["sha256:<fingerprint>", ...]},
                 "required": ["MONITOR-ID", ...]}

A fingerprint may be bound to one monitor id only, so one monitor's key never
speaks for another, and a required id must be bound. A coverage record or
heartbeat of a bound monitor counts only when its signer is one of that
monitor's keys *and* still a pinned, non-``optimizer`` ``monitor`` key
(:func:`allowed`). A monitor with no binding is reported
(``monitor.signer-unbound``): advisory by default (owner decision D12), and
under the ``rsi`` profile none of its records count (fail closed).
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

_FIELDS = {"version", "signers", "required"}


def section_of(doc: Any) -> dict[str, Any] | None:
    """``{"signers": {id: [fpr]}, "required": [id]}`` of a bundle section; ``None`` if bad."""
    from opentine._monitor_ledger import MONITOR_ID
    from opentine._trust_bundle import _PIN

    if not isinstance(doc, dict) or doc.get("version") != 1 or set(doc) - _FIELDS:
        return None
    signers, required = doc.get("signers", {}), doc.get("required", [])
    if not isinstance(signers, dict) or not isinstance(required, list):
        return None
    owner: dict[str, str] = {}
    out: dict[str, list[str]] = {}
    for ident, keys in signers.items():
        if not isinstance(ident, str) or not MONITOR_ID.fullmatch(ident):
            return None
        if not isinstance(keys, list) or not keys or not all(
                isinstance(k, str) and _PIN.fullmatch(k) for k in keys):  # fmt: skip
            return None
        for fpr in keys:
            if owner.setdefault(fpr, ident) != ident:
                return None  # one key, two monitors: neither is independent evidence
        out[ident] = sorted(set(keys))
    if not all(isinstance(r, str) and r in out for r in required):
        return None
    return {"signers": out, "required": sorted(set(required))}


class BindingError(ValueError):
    """A pinned owner whose trust bundle is missing or does not verify."""


def pinned(store: Path | None) -> dict[str, Any] | None:
    """The verified, owner-pinned ``monitors`` section; ``None`` when none is pinned.

    Under a pinned owner a missing or bad bundle is a :class:`BindingError`, as it
    is for key roles: deleting the file must not drop a required monitor.
    """
    from opentine._key_roles_pin import _serials, bundle_path, owner_vkey
    from opentine._trust_bundle import BundleError, open_bundle

    owner = owner_vkey()
    if store is None or owner is None:
        return None
    try:
        note = bundle_path(Path(store)).read_bytes()
        payload = open_bundle(note, owner, min_serial=_serials().get(owner, 0))
    except (OSError, BundleError) as exc:
        raise BindingError(f"trust bundle: {exc}") from exc
    return section_of(payload["monitors"]) if "monitors" in payload else None


def required(repo: Any) -> list[str]:
    """The required monitor ids (:class:`BindingError` when the bundle cannot be read)."""
    found = pinned(getattr(repo, "path", None))
    return found["required"] if found else []


def allowed(repo: Any, monitor: str, keys: set[str], *,
            gating: bool) -> tuple[set[str], dict[str, Any] | None]:  # fmt: skip
    """``(the keys that may sign for *monitor*, an unbound finding or None)``."""
    try:
        found = pinned(getattr(repo, "path", None))
    except BindingError:
        found = None  # unreadable: nothing is bound (and no monitor key is pinned either)
    bound = (found or {}).get("signers", {}).get(monitor)
    if bound is not None:
        return set(keys) & set(bound), None
    level = "fail" if gating else "advisory"
    finding = {"level": level, "code": f"{level}:monitor.signer-unbound", "record": None,
               "message": f"the trust bundle binds no signer key to monitor {monitor}, so any "
                          "pinned monitor key could have written its records"
                          + (" (none count under rsi)" if gating else "")}  # fmt: skip
    return (set() if gating else set(keys)), finding


def finite(value: Any) -> float | None:
    """*value* as a finite real number; ``None`` for NaN, inf, bool or a non-number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


__all__ = ["BindingError", "allowed", "finite", "pinned", "required", "section_of"]
