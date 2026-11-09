"""Hosted-beta reads (0.46): object reads, run closures, listings, log entries, admin stats.

Every function here authorizes per tenant first and then answers. A read that is
not authorized, names another tenant, or names an object the tenant does not
hold raises :class:`Hidden`, which the routes turn into one byte-identical 404:
no status, header or body tells a caller whether an oid exists anywhere.
"""

from __future__ import annotations

import base64
import binascii
import json
import threading
import time
from typing import Any

from opentine.kernel import parse_oid
from opentine.remote._tenant_repo import TenantRepo
from opentine.repository._pack_fit import fitted_pack
from opentine.repository._semantic_view import SemanticView
from opentine.repository.pack import MAX_PACK_BODY_BYTES, negotiate

MAX_PAGE = 500
DEFAULT_PAGE = 100
CLOSURE_SECONDS = 60.0
#: Immutable by oid, but only for this caller: shared caches must not keep it,
#: and ``Vary`` keeps a private cache from replaying it to another credential.
OBJECT_CACHE = (
    ("Cache-Control", "private, max-age=31536000, immutable"),
    ("Vary", "Authorization"),
)


class Hidden(LookupError):
    """Unauthorized, other tenant or absent: all answered by the same 404."""


def readable(service: Any, identity, tenant: str, action: str = "fetch") -> None:
    try:
        service._authorize(identity, action, tenant)
    except PermissionError as exc:
        raise Hidden("not found") from exc


def checked_oid(oid: str) -> str:
    try:
        parse_oid(oid)
    except (ValueError, TypeError) as exc:
        raise Hidden("not found") from exc
    return oid


def object_bytes(service: Any, tenant: str, oid: str) -> bytes:
    """The stored envelope of *oid*; per-object policy (``service.object_policy``) applies."""
    checked_oid(oid)
    policy = getattr(service, "object_policy", None)
    if callable(policy) and not policy(tenant, oid):
        raise Hidden("not found")
    try:
        return service.objects.get(tenant, oid)
    except (KeyError, ValueError) as exc:
        raise Hidden("not found") from exc


def run_pack(service: Any, tenant: str, run: str, request: dict[str, Any]) -> tuple[bytes, int]:
    """A pack of *run*'s closure minus *haves*; with ``lazy_blobs`` the blobs stay out.

    Lazy blobs become the pack's shallow boundary; the client reads each one with
    ``GET objects/<oid>``, which authorizes it on its own.
    """
    if not checked_oid(run).startswith("run:") or not service.objects.has(tenant, run):
        raise Hidden("not found")
    repo = SemanticView(
        TenantRepo(tenant, service.objects, service.index), max_source_bytes=MAX_PACK_BODY_BYTES
    )
    lazy = request.get("lazy_blobs") is True
    held: list[int] = [0]

    def select(_view, missing: list[str]) -> list[str]:
        kept = [oid for oid in missing if not (lazy and oid.startswith("blob:"))]
        held[0] = len(missing) - len(kept)
        return kept

    data, _ = fitted_pack(
        repo, [run], list(request.get("haves") or []), depth=request.get("depth"), select=select
    )
    return data, held[0]


def match_text(objects: Any, tenant: str, oid: str, text: str) -> bool:
    """Whether *oid*'s stored record holds *text*, case-insensitively (server-side search)."""
    try:
        raw = objects.get(tenant, oid)
    except (KeyError, ValueError):
        return False
    return text.casefold() in raw.decode("utf-8", "replace").casefold()


class ClosureCache:
    """A run's reachable oids, briefly cached: share reads check membership per request."""

    def __init__(self, seconds: float = CLOSURE_SECONDS, size: int = 64):
        self.seconds, self.size = seconds, size
        self._lock = threading.Lock()
        self._items: dict[tuple[str, str], tuple[float, frozenset[str]]] = {}

    def members(self, service: Any, tenant: str, run: str) -> frozenset[str]:
        now = time.monotonic()
        with self._lock:
            hit = self._items.get((tenant, run))
        if hit and hit[0] > now:
            return hit[1]
        if not service.objects.has(tenant, run):
            return frozenset()
        oids = frozenset(negotiate(TenantRepo(tenant, service.objects, service.index), [run], []))
        with self._lock:
            if len(self._items) >= self.size:
                self._items.pop(next(iter(self._items)))
            self._items[(tenant, run)] = (now + self.seconds, oids)
        return oids


def _cursor(raw: str | None) -> str:
    if not raw:
        return ""
    try:
        return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("invalid cursor") from exc


def page(keys: list[str], query: dict[str, str]) -> tuple[list[str], str | None]:
    """Keys after the opaque ``cursor``, at most ``limit``; the next cursor or ``None``."""
    try:
        limit = int(query.get("limit") or DEFAULT_PAGE)
    except ValueError as exc:
        raise ValueError("invalid limit") from exc
    if not 1 <= limit <= MAX_PAGE:
        raise ValueError(f"limit must be 1..{MAX_PAGE}")
    after = _cursor(query.get("cursor"))
    rest = [key for key in sorted(keys) if key > after]
    chunk = rest[:limit]
    more = len(rest) > limit
    token = base64.urlsafe_b64encode(chunk[-1].encode()).decode().rstrip("=") if more else None
    return chunk, token


def list_runs(service: Any, tenant: str, query: dict[str, str]) -> dict[str, Any]:
    runs = [oid for oid in service.objects.list(tenant) if oid.startswith("run:")]
    chunk, cursor = page(runs, query)
    return {"items": chunk, "next_cursor": cursor}


def list_refs(service: Any, tenant: str, query: dict[str, str]) -> dict[str, Any]:
    refs = service.index.list_refs(tenant)
    chunk, cursor = page(list(refs), query)
    return {"items": [{"name": name, "oid": refs[name]} for name in chunk], "next_cursor": cursor}


def log_entries(service: Any, tenant: str, query: dict[str, str]) -> dict[str, Any] | None:
    """This tenant's transparency-log entries with their log indexes (``log_http``)."""
    from opentine.remote._audit_tlog import origin, tlog_root
    from opentine.repository import _tlog_note

    root = tlog_root(service.audit)
    if root is None or not (root / "checkpoint").exists():
        return None
    entries = _tlog_note.verify_log(root, origin(root))
    mine = []
    for index, raw in enumerate(entries):
        if json.loads(raw).get("tenant") == tenant:
            mine.append(f"{index:012d}")
    chunk, cursor = page(mine, query)
    items = [{"index": int(i), "entry": entries[int(i)].decode("utf-8")} for i in chunk]
    return {"items": items, "next_cursor": cursor, "size": len(entries)}


def admin_stats(service: Any, tenant: str) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for oid in service.objects.list(tenant):
        kind = oid.split(":", 1)[0]
        counts[kind] = counts.get(kind, 0) + 1
    shares = getattr(service, "shares", None)
    active = sum(1 for row in shares.list(tenant) if row["state"] == "active") if shares else 0
    refs = len(service.index.list_refs(tenant))
    return {"objects": dict(sorted(counts.items())), "refs": refs, "shares_active": active}


__all__ = [
    "OBJECT_CACHE",
    "ClosureCache",
    "Hidden",
    "admin_stats",
    "list_refs",
    "list_runs",
    "match_text",
    "log_entries",
    "object_bytes",
    "page",
    "readable",
    "run_pack",
]
