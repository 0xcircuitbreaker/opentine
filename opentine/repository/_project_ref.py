"""A repository's project manifest: the ``project/manifest`` ref (0.46.1, SPEC 4.16).

Each version is stored as a blob of its canonical bytes (never redacted: a
manifest holds no secret, and a private upstream is a commitment), so a
version's ``prev`` is the blob oid of its predecessor and the history walks the
object store. :func:`write` checks the new version against the current one
(``opentine._project.check``: chain link and an owner's signature) before the
ref moves by compare-and-swap.

The URL and salt that open a private slot's commitment never enter a manifest:
they stay in ``.tine/project-locators.json`` beside this repository, which is
not pushed, bundled or served.
"""

from __future__ import annotations

import json
from typing import Any

from opentine import _project
from opentine.kernel import canonical_json
from opentine.repository._paths import atomic_bytes, internal_path
from opentine.repository._refs import PROJECT_REF

LOCATORS = "project-locators.json"
MAX_HISTORY = 10_000


def _load(repo: Any, oid: str) -> dict[str, Any]:
    return json.loads(repo.get(oid).payload())


def head(repo: Any) -> str | None:
    """The blob oid ``project/manifest`` names, or ``None``."""
    return repo.read_ref(PROJECT_REF)


def read(repo: Any) -> dict[str, Any] | None:
    oid = head(repo)
    return None if oid is None else _load(repo, oid)


def history(repo: Any, *, limit: int = MAX_HISTORY) -> list[dict[str, Any]]:
    """Every version, oldest first, by following ``prev`` from the head."""
    out: list[dict[str, Any]] = []
    oid = head(repo)
    while oid is not None and len(out) < limit:
        record = _load(repo, oid)
        out.append(record)
        oid = record.get("prev")
    return list(reversed(out))


def write(repo: Any, record: dict[str, Any], *, owner_key: str | None = None) -> str:
    """Store *record* as the next version; return its blob oid. Refuses a bad link or signer."""
    current_oid = head(repo)
    current = None if current_oid is None else _load(repo, current_oid)
    _project.check(record, previous=current, owner_key=owner_key if current is None else None)
    oid = repo.put("blob", canonical_json(record), redact=False)
    if oid != _project.digest(record):
        raise ValueError("the stored manifest blob does not match its digest")
    repo.update_ref(PROJECT_REF, oid, expected_old=current_oid)
    return oid


def install(repo: Any, versions: list[dict[str, Any]]) -> int:
    """Adopt a fetched history that extends this repository's; return the versions added."""
    _project.chain(versions)
    known = {_project.digest(record) for record in history(repo)}
    current = head(repo)
    if current is not None and current not in {_project.digest(r) for r in versions}:
        raise ValueError("the fetched project history does not extend the local one")
    added = 0
    for record in versions:
        if _project.digest(record) not in known:
            write(repo, record)
            added += 1
    return added


def locators(repo: Any) -> dict[str, dict[str, str]]:
    """``{commitment: {"url", "salt"}}`` for this repository's private slots."""
    path = internal_path(repo.path, LOCATORS)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{LOCATORS} is malformed")
    return value


def remember(repo: Any, commitment: str, url: str, salt: bytes) -> None:
    found = locators(repo)
    found[commitment] = {"url": url, "salt": salt.hex()}
    atomic_bytes(internal_path(repo.path, LOCATORS), canonical_json(found))


__all__ = ["LOCATORS", "head", "history", "install", "locators", "read", "remember", "write"]
