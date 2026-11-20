"""Where key roles get their power (0.59): an owner-signed trust bundle.

``.tine/key-roles.toml`` is a file in the repository, so a loop that can write
the repository can add its own key to ``policy``, ``scorer`` or ``stopper``.
From 0.59 those roles grant powers only when they come from a trust bundle
(SPEC 8.26, :mod:`opentine._trust_bundle`) whose payload carries them as
``"key_roles": {"version": 1, "roles": {...}}`` and whose owner key is pinned
*outside* the repository:

* the owner verifier key (``name+hash+key``): ``$OPENTINE_TRUST_OWNER``, else
  the file ``$XDG_CONFIG_HOME/opentine/trust-owner`` (one line);
* the bundle: ``$OPENTINE_TRUST_BUNDLE``, else ``.tine/trust-bundle.note``
  (in the repository is fine: it is signed);
* rollback: the highest serial accepted per owner is kept in
  ``$XDG_CONFIG_HOME/opentine/trust-bundle-serials.json``; a lower serial is
  refused as in 0.51.

:func:`resolve` answers ``{"roles", "status", "source"}`` where ``status`` is
``pinned`` (roles from a verified bundle), ``unpinned`` (only the unsigned
file, or a bundle with no pinned owner) or ``absent``. A pinned owner with a
bad, stale or rolled-back bundle raises :class:`KeyRoleError`: fail closed.
Unpinned roles may still *refuse* (key separation); they never grant.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from opentine._key_roles import FILE_NAME, KeyRoleError, load, parse_doc

BUNDLE_NAME = "trust-bundle.note"
OWNER_ENV = "OPENTINE_TRUST_OWNER"
BUNDLE_ENV = "OPENTINE_TRUST_BUNDLE"
UNPINNED = ("key roles are unpinned: no trust bundle signed by an owner key pinned outside "
            "the repository names them (tine trust bundle create --key-roles)")  # fmt: skip


def _config_dir() -> Path:
    from opentine._trust_policy import policy_file

    return policy_file().parent


def owner_vkey() -> str | None:
    """The pinned owner verifier key, or ``None`` when none is pinned."""
    value = os.environ.get(OWNER_ENV, "").strip()
    if not value:
        try:
            value = (_config_dir() / "trust-owner").read_bytes().decode("utf-8").strip()
        except (OSError, UnicodeDecodeError):
            value = ""
    return value or None


def _serials() -> dict[str, int]:
    try:
        data = json.loads((_config_dir() / "trust-bundle-serials.json").read_bytes())
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if type(v) is int} if isinstance(data, dict) else {}


def _remember(owner: str, serial: int) -> None:
    seen = _serials()
    if seen.get(owner, 0) >= serial:
        return
    seen[owner] = serial
    path = _config_dir() / "trust-bundle-serials.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((json.dumps(seen, sort_keys=True) + "\n").encode("utf-8"))
    except OSError:
        pass  # a read-only config: the floor stays where it was


def bundle_path(store: Path) -> Path:
    named = os.environ.get(BUNDLE_ENV, "").strip()
    return Path(named) if named else Path(store) / BUNDLE_NAME


def _from_bundle(store: Path, owner: str) -> dict[str, list[str]] | None:
    from opentine._trust_bundle import BundleError, open_bundle

    try:
        note = bundle_path(store).read_bytes()
    except FileNotFoundError as exc:
        # A pinned owner and no bundle fails closed: deleting the file is not a downgrade.
        raise KeyRoleError(f"trust bundle missing for the pinned owner: {exc}") from exc
    except OSError as exc:
        raise KeyRoleError(f"trust bundle: {exc}") from exc
    try:
        payload = open_bundle(note, owner, min_serial=_serials().get(owner, 0))
    except BundleError as exc:
        raise KeyRoleError(f"trust bundle: {exc}") from exc
    _remember(owner, payload["serial"])
    return parse_doc(payload["key_roles"]) if "key_roles" in payload else None


def resolve(store: Path | None) -> dict[str, Any]:
    """``{"roles", "status", "source"}`` for a repository's ``.tine`` directory."""
    if store is None:
        return {"roles": None, "status": "absent", "source": None}
    owner = owner_vkey()
    if owner is not None:
        roles = _from_bundle(Path(store), owner)
        if roles is not None:
            return {"roles": roles, "status": "pinned", "source": "trust-bundle"}
    roles = load(Path(store) / FILE_NAME)
    if roles is not None:
        return {"roles": roles, "status": "unpinned", "source": FILE_NAME}
    there = bundle_path(Path(store)).is_file()
    return {"roles": None, "status": "unpinned" if there else "absent", "source": None}


def pinned(store: Path | None) -> dict[str, list[str]] | None:
    """The roles that may grant powers: only those from a pinned bundle."""
    found = resolve(store)
    return found["roles"] if found["status"] == "pinned" else None


__all__ = ["BUNDLE_NAME", "UNPINNED", "bundle_path", "owner_vkey", "pinned", "resolve"]
