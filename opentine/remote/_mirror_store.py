"""A tenant's code mirror: ``<objects root>/.mirrors/<tenant>/`` (0.55, ``caps.project.mirror``).

Off unless the operator turns it on (``tine serve --mirror``). A mirror is
*linked* to the primary (or secondary) slot of the tenant's current
``opentine.project`` manifest and holds:

* ``git/``: a bare, fetch-only copy of the upstream's heads and tags;
* ``link.json``: the upstream URL (never its credential: ``_mirror_secret``), the
  slot and the manifest it was linked under;
* ``state.json``: the last sync, as the body of an ``opentine.mirror-state``
  (frozen, SPEC 4.17): a host statement, never a user's;
* ``search.sqlite3``: the code-search cache (``_mirror_search``).

Unlinking removes the whole directory: mirror, state and caches. A sync is
polled every ``poll_seconds`` or triggered by a webhook (``POST
project/mirror/sync``), never more often than ``min_interval_seconds``. A
public project over private code is refused when the mirror is linked.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine import _mirror_git as gitio
from opentine import _mirror_state, _project
from opentine._mirror_fetch import remove_tree
from opentine._utc import rfc3339_utc
from opentine.remote import _mirror_secret, _project_store
from opentine.remote.backend import valid_tenant

DEFAULTS: dict[str, Any] = {
    "poll_seconds": 300,
    "min_interval_seconds": 30,
    "sync_timeout_seconds": 120,
    "max_repo_bytes": 512 * 1024 * 1024,
    "max_refs": 1000,
    "max_blob_bytes": 1024 * 1024,
    "max_page": 100,
    "allow_local": False,
    "poller": False,
}
_LOCKS: dict[str, threading.Lock] = {}
_GUARD = threading.Lock()


class Refused(PermissionError):
    """A mirror request refused on policy (``code`` names why)."""

    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


class TooSoon(RuntimeError):
    def __init__(self, retry_after: int):
        super().__init__("synced too recently")
        self.retry_after = retry_after


def config(raw: dict[str, Any] | None) -> dict[str, Any]:
    unknown = set(raw or {}) - set(DEFAULTS)
    if unknown:
        raise ValueError(f"unknown mirror setting {sorted(unknown)[0]}")
    return {**DEFAULTS, **(raw or {})}


def directory(root: Path, tenant: str) -> Path:
    return Path(root) / ".mirrors" / valid_tenant(tenant)


def _lock(root: Path, tenant: str) -> threading.Lock:
    with _GUARD:
        return _LOCKS.setdefault(str(directory(root, tenant)), threading.Lock())


def _read(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_bytes())
    except (FileNotFoundError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _write(path: Path, value: dict[str, Any]) -> None:
    """Owner-only (0600): a private slot's upstream URL is in link.json."""
    temp = path.with_suffix(".tmp")
    temp.unlink(missing_ok=True)
    handle = os.open(
        temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(handle, "w", encoding="utf-8") as out:
        out.write(json.dumps(value, sort_keys=True))
    temp.replace(path)


def link_of(root: Path, tenant: str) -> dict[str, Any] | None:
    return _read(directory(root, tenant) / "link.json")


def state_of(root: Path, tenant: str) -> dict[str, Any] | None:
    return _read(directory(root, tenant) / "state.json")


def repo(root: Path, tenant: str) -> Path:
    return directory(root, tenant) / "git"


def _slot(manifest: dict[str, Any], role: str) -> dict[str, Any]:
    for slot in manifest["slots"]:
        if slot["role"] == role:
            return slot
    raise Refused("the project has no such slot", "mirror.no-slot")


def link(root: Path, tenant: str, request: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    """Link the mirror to a slot of the current manifest (a private one needs url + salt).

    With ``allow_local`` (self-host and tests only) a ``file://`` *url* stands in for a
    public slot's upstream; the label still names the manifest's URL.
    """
    manifest = _project_store.head(root, tenant)
    if manifest is None:
        raise Refused("link a project manifest first", "mirror.no-project")
    role = request.get("slot") or "primary"
    slot = _slot(manifest, role if isinstance(role, str) else "")
    private_code = slot["upstream_visibility"] == "private" or request.get("private") is True
    if manifest["visibility"] == "public" and private_code:
        raise Refused("a public project over private code is refused", "mirror.private-upstream")
    locator = slot["locator"]
    if "url" in locator:
        url, shown = locator["url"], locator["url"]
        local = request.get("url")
        if local is not None and local != url:
            if not (cfg["allow_local"] and isinstance(local, str) and local.startswith("file://")):
                raise Refused("a public slot mirrors the manifest's url", "mirror.locator")
            url = local
    else:
        url, salt = request.get("url"), request.get("salt")
        try:
            opened = isinstance(url, str) and _project.opens(locator, url, bytes.fromhex(salt))
        except (TypeError, ValueError):
            opened = False
        if not opened:
            raise Refused("url and salt must open the slot's commitment", "mirror.locator")
        shown = locator["commitment"]
    url, credential = _mirror_secret.split(url)  # userinfo never reaches link.json
    record = {"upstream": url, "shown": _mirror_secret.strip(shown), "slot": role,
              "visibility": manifest["visibility"],
              "manifest": _project.digest(manifest), "default_branch": slot["default_branch"],
              "project_id": manifest["project_id"]}  # fmt: skip
    place = directory(root, tenant)
    place.mkdir(mode=0o700, parents=True, exist_ok=True)
    _mirror_secret.save(place, credential)
    _write(place / "link.json", record)
    return record


def unlink(root: Path, tenant: str) -> bool:
    """Delete the mirror, its state and every cache; whether anything was there."""
    place = directory(root, tenant)
    with _lock(root, tenant):
        existed = place.exists()
        remove_tree(place)  # raises rather than leave the mirror behind
    return existed


def _epoch(when: str) -> float:
    return datetime.strptime(when, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()


def sync(root: Path, tenant: str, cfg: dict[str, Any], *, force: bool = False,
         now: float | None = None, max_bytes: int | None = None) -> dict[str, Any]:  # fmt: skip
    """Fetch the upstream and record a mirror state; ``TooSoon`` inside the interval."""
    linked = link_of(root, tenant)
    if linked is None:
        raise LookupError("no mirror")
    now = time.time() if now is None else now
    with _lock(root, tenant):
        before = state_of(root, tenant)
        if before is not None and not force:
            waited = now - _epoch(before["synced_at"])
            if waited < cfg["min_interval_seconds"]:
                raise TooSoon(max(1, int(cfg["min_interval_seconds"] - waited)))
        limit = min(cfg["max_repo_bytes"], max_bytes or cfg["max_repo_bytes"])
        found: dict[str, str] = {}
        fmt, status, reasons = "sha1", "synced", []
        try:
            gitio.fetch(linked["upstream"], repo(root, tenant), allow_local=cfg["allow_local"],
                        timeout=cfg["sync_timeout_seconds"], max_bytes=limit,
                        credential=_mirror_secret.load(directory(root, tenant)))  # fmt: skip
            fmt, found = gitio.object_format(repo(root, tenant)), gitio.refs(repo(root, tenant))
            if len(found) > cfg["max_refs"]:
                found, status, reasons = {}, "paused", ["mirror.limit-exceeded"]
        except gitio.GitError as exc:
            code = exc.code if exc.code in _mirror_state.MIRROR_CODES else "mirror.stale"
            status = "paused" if code == "mirror.limit-exceeded" else "failed"
            if status == "failed" and _mirror_state.REPORT_CODES[code] != "unavailable":
                code = "mirror.upstream-unreachable"
            found = before["refs"] if before and status == "failed" else {}
            reasons = sorted({code, "mirror.stale"} if found else {code})
        state = {"kind": _mirror_state.KIND, "mirror_state_version": 1, "tenant": tenant,
                 "project_id": linked["project_id"], "manifest": linked["manifest"],
                 "slot": linked["slot"], "object_format": fmt, "refs": found,
                 "synced_at": _stamp(now), "status": status,
                 "reasons": reasons}  # fmt: skip
        _mirror_state.consistent(_mirror_state.body(state))
        _write(directory(root, tenant) / "state.json", state)
        if status == "synced":  # under the lock, so an unlink cannot race the cache back
            from opentine.remote import _mirror_push, _mirror_search

            _mirror_search.rebuild(root, tenant, linked["default_branch"])
            _mirror_push.spool(directory(root, tenant), _mirror_push.pushes(before, state))
    return state


def _stamp(epoch: float) -> str:
    return rfc3339_utc(epoch)


def due(root: Path, cfg: dict[str, Any], now: float) -> list[str]:
    """Tenants whose mirror was last synced ``poll_seconds`` or more before *now*."""
    out = []
    for place in sorted((Path(root) / ".mirrors").glob("*/link.json")):
        state = state_of(root, place.parent.name)
        if state is None or now - _epoch(state["synced_at"]) >= cfg["poll_seconds"]:
            out.append(place.parent.name)
    return out


def poll(root: Path, cfg: dict[str, Any], now: float | None = None) -> list[str]:
    """Sync every due mirror once (the ``tine serve --mirror`` poller calls this)."""
    now = time.time() if now is None else now
    synced = []
    for tenant in due(root, cfg, now):
        try:
            sync(root, tenant, cfg, force=True, now=now)
            synced.append(tenant)
        except (LookupError, TooSoon, ValueError, OSError):
            continue
    return synced


__all__ = ["DEFAULTS", "Refused", "TooSoon", "config", "directory", "due", "link", "link_of",
           "poll", "repo", "state_of", "sync", "unlink"]  # fmt: skip
