"""Operator maintenance for the reference remote: delete refs and objects, purge.

The remote had no way to remove anything: an annotation ref over a budget, a flood
of attestations on someone's run, or the objects a deleted ref left behind could
only be removed by editing SQLite by hand. These operations open the server's
storage directly (``tine serve --root R --tenant T ACTION``) instead of adding an
HTTP endpoint, so no token, however privileged, reaches them over the network.

They are safe beside a live server. A ref delete is compare-and-swap. Purge keeps
everything a ref reaches -- with the annotations and attestations a fetch would
carry -- and every object written within the grace window, so a push between its
pack install and its ref update keeps its objects. It deletes in batches, each in
a SQLite write transaction that re-reads the refs and the objects installed since
the scan, so nothing a ref gains meanwhile is removed. An object that cannot be
decoded is never removed. Every action, dry runs included, is audited.
"""

from __future__ import annotations

import getpass
import hashlib
import math
import os
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine.kernel import parse_oid
from opentine.remote._admin_backend import forget, installed_since, ref_targets
from opentine.remote._admin_graph import scan
from opentine.remote.backend import FilesystemObjectStore, SQLiteBackend, valid_tenant
from opentine.remote.interfaces import AuditEvent, KeyProvider
from opentine.remote.security import LocalKeyProvider
from opentine.repository._refs import normalize_ref

PURGE_BATCH = 500
MAX_LISTED_ASSOCIATIONS = 10_000
MAX_DELETE_OBJECTS = 10_000


@dataclass(frozen=True)
class AdminResult:
    action: str
    tenant: str
    dry_run: bool
    removed: tuple[str, ...] = ()
    kept: int = 0
    #: Unreachable from every ref, but written within the grace window.
    deferred: int = 0
    #: Vetoed by the object store's retention hook.
    retained: tuple[str, ...] = ()
    #: Could not be decoded, so their links are unknown; never removed.
    unreadable: tuple[str, ...] = ()


def _digest(oids: Iterable[str]) -> str:
    return "sha256:" + hashlib.sha256("\n".join(sorted(oids)).encode()).hexdigest()


def _actor() -> str:
    try:
        user = getpass.getuser()
    except (KeyError, OSError):
        return "operator"
    return f"operator:{user}" if user and user.isprintable() else "operator"


class RemoteAdmin:
    def __init__(self, objects: FilesystemObjectStore, index: SQLiteBackend, *, actor: str = ""):
        self.objects = objects
        self.index = index
        self.actor = actor or _actor()

    @classmethod
    def open(
        cls, root: str | Path, *, keys: KeyProvider | None = None, audit_key: bytes | None = None
    ) -> RemoteAdmin:
        """The storage ``tine serve --root`` uses, opened the way the server opens it."""
        state = Path(root).resolve()
        if not (state / "metadata.sqlite3").is_file():
            raise FileNotFoundError(f"no reference remote at {state}")
        key_provider = keys or LocalKeyProvider.from_env()
        chain_key = audit_key or key_provider.derive_audit_key()
        objects = FilesystemObjectStore(state / "objects", key_provider)
        return cls(objects, SQLiteBackend(state / "metadata.sqlite3", audit_key=chain_key))

    def _audit(self, tenant: str, action: str, outcome: str, details: dict[str, Any]) -> None:
        when = datetime.now(UTC).isoformat()
        event = AuditEvent(str(uuid.uuid4()), when, tenant, self.actor, action, outcome, details)
        self.index.append(event)

    def refs(self, tenant: str) -> dict[str, str]:
        """The raw ref table, readable even when ``GET /refs`` refuses the listing."""
        tenant = valid_tenant(tenant)
        with self.index.exclusive() as database:
            refs = ref_targets(database, tenant)
        self._audit(tenant, "admin_read_refs", "ok", {"refs": len(refs)})
        return dict(sorted(refs.items()))

    def associations(self, tenant: str, target: str) -> list[dict[str, str]]:
        tenant = valid_tenant(tenant)
        parse_oid(target)
        rows = self.index.associations_with_times(tenant, target, MAX_LISTED_ASSOCIATIONS)
        self._audit(tenant, "admin_read_associations", "ok", {"target": target, "count": len(rows)})
        return [{"oid": oid, "installed_at": when} for oid, when in rows]

    def delete_ref(self, tenant: str, name: str, expected: str | None = None) -> bool:
        tenant, name = valid_tenant(tenant), normalize_ref(name)
        if expected is not None:
            parse_oid(expected)
        deleted = self.index.delete_ref(tenant, name, expected)
        details = {"expected_old": expected, "name": name}
        self._audit(tenant, "admin_delete_ref", "ok" if deleted else "conflict", details)
        return deleted

    def delete_objects(self, tenant: str, oids: Iterable[str], *, dry_run: bool = False):
        """Remove objects no ref reaches except as associations (e.g. an attestation flood)."""
        tenant = valid_tenant(tenant)
        targets = sorted(set(oids))
        if not 0 < len(targets) <= MAX_DELETE_OBJECTS:
            raise ValueError(f"delete between 1 and {MAX_DELETE_OBJECTS} objects at a time")
        for oid in targets:
            parse_oid(oid)
        graph = scan(self.objects, self.index, tenant)
        absent = [oid for oid in targets if oid not in graph.listed]
        if absent:
            raise KeyError(f"not stored in {tenant}: {absent[0]}")
        details: dict[str, Any] = {"count": len(targets), "digest": _digest(targets)}
        if not dry_run:
            self._audit(tenant, "admin_delete_objects", "started", details)
        refusal = ""
        removed: list[str] = []
        retained: list[str] = []
        with self.index.exclusive() as database:
            refs = set(ref_targets(database, tenant).values())
            fresh = installed_since(database, tenant, graph.since) - graph.listed
            linked = graph.live(refs | fresh, excluded=set(targets)) & set(targets)
            if refs & set(targets):
                refusal = "a ref names an object to delete; delete the ref first"
            elif linked:
                refusal = f"{min(linked)} is still linked from objects a ref reaches"
            elif not dry_run:
                removed, retained = self._remove(database, tenant, targets)
        if refusal:
            self._audit(tenant, "admin_delete_objects", "refused", {**details, "reason": refusal})
            raise ValueError(refusal)
        outcome = "dry-run" if dry_run else "ok"
        self._audit(tenant, "admin_delete_objects", outcome, {**details, "retained": len(retained)})
        removed = targets if dry_run else removed
        return AdminResult("delete-objects", tenant, dry_run, tuple(removed), 0, 0, tuple(retained))

    def purge(self, tenant: str, *, grace_seconds: float = 3600, dry_run: bool = False):
        """Remove objects no ref reaches that are older than *grace_seconds*."""
        tenant = valid_tenant(tenant)
        if isinstance(grace_seconds, bool) or not math.isfinite(grace_seconds) or grace_seconds < 0:
            raise ValueError("grace window must be a non-negative number of seconds")
        graph = scan(self.objects, self.index, tenant)
        now = time.time()
        recent = {oid for oid in graph.listed if self._age(tenant, oid, now) < grace_seconds}
        with self.index.exclusive() as database:
            refs = ref_targets(database, tenant)
        roots = set(refs.values()) | recent
        live = graph.live(roots)
        deferred = len(live - graph.live(refs.values()))
        unreadable = sorted(graph.unreadable & graph.listed)
        candidates = sorted(graph.listed - live - graph.unreadable)
        details = {"candidates": len(candidates), "digest": _digest(candidates)}
        details.update(grace_seconds=grace_seconds, deferred=deferred, unreadable=len(unreadable))
        removed: list[str] = []
        retained: list[str] = []
        if dry_run:
            removed = candidates
        else:
            self._audit(tenant, "admin_purge", "started", details)
            for start in range(0, len(candidates), PURGE_BATCH):
                with self.index.exclusive() as database:
                    roots |= set(ref_targets(database, tenant).values())
                    roots |= installed_since(database, tenant, graph.since) - graph.listed
                    live = graph.live(roots)
                    # Age again under the lock: an install fences what it wrote or
                    # links to by refreshing it inside this same lock (_install_fence).
                    now = time.time()
                    batch = [
                        oid
                        for oid in candidates[start : start + PURGE_BATCH]
                        if oid not in live and self._age(tenant, oid, now) >= grace_seconds
                    ]
                    gone, vetoed = self._remove(database, tenant, batch)
                removed.extend(gone)
                retained.extend(vetoed)
        result = {
            "removed": len(removed),
            "removed_digest": _digest(removed),
            "retained": len(retained),
        }
        self._audit(tenant, "admin_purge", "dry-run" if dry_run else "ok", {**details, **result})
        kept = len(graph.listed) - len(removed)
        return AdminResult(
            "purge",
            tenant,
            dry_run,
            tuple(removed),
            kept,
            deferred,
            tuple(retained),
            tuple(unreadable),
        )

    def _age(self, tenant: str, oid: str, now: float) -> float:
        try:
            return now - os.lstat(self.objects._path(tenant, oid)).st_mtime
        except FileNotFoundError:
            return math.inf

    def _remove(self, database, tenant: str, oids: list[str]) -> tuple[list[str], list[str]]:
        removed: list[str] = []
        retained: list[str] = []
        for oid in oids:
            try:
                self.objects.delete(tenant, oid)
            except PermissionError:
                retained.append(oid)
                continue
            except FileNotFoundError:
                pass
            removed.append(oid)
        forget(database, tenant, removed)
        return removed, retained
