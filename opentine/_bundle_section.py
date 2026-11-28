"""One named section of the owner-pinned trust bundle (0.91).

The trust bundle (:mod:`opentine._trust_bundle`) is signed by an owner key
pinned outside the repository (:mod:`opentine._key_roles_pin`). A section in it
is a rule the repository cannot edit: :func:`section` returns it parsed by the
section's own ``section_of``, ``None`` when no owner is pinned or the bundle
does not carry it, and raises :class:`SectionError` when an owner is pinned and
the bundle is missing, rolled back or does not verify, so deleting the file is
never a way to drop a rule (fail closed).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any


class SectionError(ValueError):
    """A pinned owner whose trust bundle is missing or does not verify."""


def section(store: Path | None, name: str, parse: Callable[[Any], Any]) -> Any | None:
    from opentine._key_roles_pin import _serials, bundle_path, owner_vkey
    from opentine._trust_bundle import BundleError, open_bundle

    owner = owner_vkey()
    if store is None or owner is None:
        return None
    try:
        note = bundle_path(Path(store)).read_bytes()
        payload = open_bundle(note, owner, min_serial=_serials().get(owner, 0))
    except (OSError, BundleError) as exc:
        raise SectionError(f"trust bundle: {exc}") from exc
    return parse(payload[name]) if name in payload else None


__all__ = ["SectionError", "section"]
