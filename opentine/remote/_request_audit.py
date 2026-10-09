"""Audit what the remote refuses, not only what it does.

Successful requests were audited; refusals mostly were not. A request with a bad
or missing token got 401 with no record, an identity whose tenant claim was not
a valid tenant name got 400 with none (its denial could not be written under
that tenant), and a request that failed after authorization -- an invalid pack
or ref, an admission refusal, an upload that belongs to someone else -- left
nothing either. Now:

* an authenticated failure is audited under its tenant, like a success;
* unauthenticated refusals are counted and written at most once per
  ``interval`` per (tenant named in the URL, reason) -- so anonymous traffic
  cannot grow the log faster than that -- under :data:`SERVER_TENANT` when the
  URL names no valid tenant or too many distinct ones arrive at once.

Auditing a failure is best effort: it never turns the refusal into a 500.
Nothing secret is written -- no token, header or body, only the exception type.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from opentine.remote._audit import SERVER_TENANT
from opentine.remote.backend import valid_tenant
from opentine.remote.interfaces import AuditEvent

_MAX_PENDING_KEYS = 64
_ACTIONS = {
    ("refs", "GET"): "read_ref",
    ("refs/", "PUT"): "update_ref",
    ("negotiate", "POST"): "negotiate",
    ("fetch", "POST"): "fetch",
    ("packs", "POST"): "upload",
    ("packs/", "HEAD"): "upload",
    ("packs/", "PATCH"): "upload",
    ("search", "POST"): "search",
    ("audit/verify", "GET"): "audit",
}


class AuthorizationDenied(PermissionError):
    """A denial the service has already audited."""


def audit_tenant(*candidates: str | None) -> str:
    """The first candidate that is a valid tenant, else the server's own."""
    for candidate in candidates:
        try:
            return valid_tenant(candidate or "")
        except (TypeError, ValueError):
            continue
    return SERVER_TENANT


def request_action(resource: str, method: str) -> str:
    key = "refs/" if resource.startswith("refs/") else resource
    key = "packs/" if key.startswith("packs/") else key
    return _ACTIONS.get((key, method), "request")


class FailureAudit:
    def __init__(self, sink: Any, *, interval: float = 60.0, clock: Callable = time.monotonic):
        self.sink = sink
        self.interval = interval
        self.clock = clock
        self._guard = threading.Lock()
        self._pending: Counter[tuple[str, str]] = Counter()
        self._flushed = -float("inf")

    def _append(self, tenant: str, actor: str, action: str, outcome: str, details) -> None:
        when = datetime.now(UTC).isoformat()
        event = AuditEvent(str(uuid.uuid4()), when, tenant, actor, action, outcome, details)
        try:
            self.sink.append(event)
        except Exception:  # noqa: BLE001 -- best effort (or no sink); the refusal stands
            pass

    def unauthenticated(self, tenant_hint: str | None, reason: str) -> None:
        with self._guard:
            key = (audit_tenant(tenant_hint), reason)
            if key not in self._pending and len(self._pending) >= _MAX_PENDING_KEYS:
                key = (SERVER_TENANT, reason)
            self._pending[key] += 1
            now = self.clock()
            if now - self._flushed < self.interval:
                return
            batch, self._pending, self._flushed = self._pending, Counter(), now
        for (tenant, why), count in sorted(batch.items()):
            details = {"count": count, "reason": why}
            self._append(tenant, "anonymous", "authenticate", "denied", details)

    def failed(self, identity: Any, tenant: str, action: str, error: BaseException) -> None:
        outcome = "denied" if isinstance(error, PermissionError) else "error"
        where = audit_tenant(identity.tenant, tenant)
        details = {"error": type(error).__name__}
        if where != tenant:
            details["requested_tenant"] = audit_tenant(tenant)
        self._append(where, identity.subject, action, outcome, details)
