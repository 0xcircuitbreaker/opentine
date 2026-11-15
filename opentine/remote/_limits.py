"""Per-tenant quotas of ``tine serve`` (0.52): published, enforced, never deleting.

Every feature and all verification are free (decision D3); hosted use has
fair-use limits. Four are metered per tenant:

=====================  ==========  ===========================================
limit                  window      exceeded
=====================  ==========  ===========================================
``storage_bytes``      total       ``507 Insufficient Storage`` on a pack upload
``egress_bytes``       UTC day     ``429`` with ``Retry-After`` (next UTC day)
``mirror_bytes``       total       ``507`` (enforced by the 0.54 code mirror)
``runner_minutes``     UTC month   ``429`` (enforced by the 0.54 hosted runner)
=====================  ==========  ===========================================

A refusal changes nothing that is stored: no quota ever deletes, expires or
rewrites an object or a ref. ``GET /v1/limits`` publishes the defaults (and the
policy), ``GET /v1/tenants/{tenant}/usage`` a tenant's limits and use. Storage
is metered from the bytes of packs this server accepted since the ledger
(``<root>/usage.sqlite3``) was created: an upper bound, since deduplicated
objects count again. ``--limits FILE`` overrides the defaults, for every
tenant (``"defaults"``) or one (``"tenants": {"acme": {...}}``); ``null`` is
unlimited.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GIB = 1024**3
#: The published fair-use defaults (decision D3).
FAIR_USE: dict[str, int | None] = {
    "storage_bytes": 10 * GIB,
    "egress_bytes": 20 * GIB,
    "mirror_bytes": 2 * GIB,
    "runner_minutes": 2000,
}
WINDOWS = {"storage_bytes": "total", "egress_bytes": "day", "mirror_bytes": "total",
           "runner_minutes": "month"}  # fmt: skip
STATUS = {"storage_bytes": 507, "egress_bytes": 429, "mirror_bytes": 507, "runner_minutes": 429}
POLICY = (
    "Every feature and all verification are free. Hosted use is metered against fair-use "
    "limits; exceeding one refuses the request (429 or 507) and never deletes anything."
)


class LimitExceeded(RuntimeError):
    def __init__(self, metric: str, retry_after: int | None):
        super().__init__(f"{metric} quota exceeded")
        self.metric = metric
        self.status = STATUS[metric]
        self.retry_after = retry_after


def _limits(raw: Any, label: str) -> dict[str, int | None]:
    if not isinstance(raw, dict) or set(raw) - set(FAIR_USE):
        raise ValueError(f"{label}: limits are {', '.join(FAIR_USE)}")
    for key, value in raw.items():
        bad = isinstance(value, bool) or not isinstance(value, int) or value < 0
        if value is not None and bad:
            raise ValueError(f"{label}.{key}: a limit is a non-negative integer or null")
    return dict(raw)


class Limits:
    def __init__(self, root: str | Path, config: dict[str, Any] | None = None, *,
                 now: Callable[[], float] = time.time):  # fmt: skip
        config = config or {}
        if set(config) - {"defaults", "tenants"}:
            raise ValueError("a limits file has defaults and tenants")
        self.defaults = {**FAIR_USE, **_limits(config.get("defaults", {}), "defaults")}
        tenants = config.get("tenants", {})
        if not isinstance(tenants, dict):
            raise ValueError("tenants maps a tenant to its limits")
        self.tenants = {name: _limits(value, name) for name, value in tenants.items()}
        self.now = now
        self.path = Path(root) / "usage.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._run("CREATE TABLE IF NOT EXISTS usage (tenant TEXT, metric TEXT, win TEXT, "
                  "amount INTEGER NOT NULL, PRIMARY KEY (tenant, metric, win))")  # fmt: skip

    @classmethod
    def from_file(cls, root: str | Path, path: str | Path | None) -> Limits:
        config = json.loads(Path(path).read_text(encoding="utf-8")) if path else None
        return cls(root, config)

    def _run(self, sql: str, args: tuple = ()) -> list[tuple]:
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            return db.execute(sql, args).fetchall()
        finally:
            db.close()

    def _window(self, metric: str) -> tuple[str, int | None]:
        moment = datetime.fromtimestamp(self.now(), UTC)
        kind = WINDOWS[metric]
        if kind == "total":
            return "total", None
        if kind == "day":
            left = 86400 - (moment.hour * 3600 + moment.minute * 60 + moment.second)
            return moment.strftime("%Y-%m-%d"), left
        return moment.strftime("%Y-%m"), 86400  # retry daily within a month window

    def limit(self, tenant: str, metric: str) -> int | None:
        return {**self.defaults, **self.tenants.get(tenant, {})}[metric]

    def used(self, tenant: str, metric: str) -> int:
        window, _ = self._window(metric)
        rows = self._run("SELECT amount FROM usage WHERE tenant=? AND metric=? AND win=?",
                         (tenant, metric, window))  # fmt: skip
        return int(rows[0][0]) if rows else 0

    def check(self, tenant: str, metric: str, adding: int = 0) -> None:
        """Raise :class:`LimitExceeded` if *adding* (or, for 0, any more) would exceed."""
        limit = self.limit(tenant, metric)
        if limit is None:
            return
        used = self.used(tenant, metric)
        if used + adding > limit or (adding == 0 and used >= limit):
            raise LimitExceeded(metric, self._window(metric)[1])

    def charge(self, tenant: str, metric: str, amount: int) -> None:
        if amount <= 0:
            return
        window, _ = self._window(metric)
        with self._lock:
            self._run(
                "INSERT INTO usage VALUES (?,?,?,?) ON CONFLICT(tenant, metric, win) "
                "DO UPDATE SET amount = amount + excluded.amount",
                (tenant, metric, window, int(amount)),
            )

    def document(self) -> dict[str, Any]:
        """``GET /v1/limits``: unsigned, the server's defaults and policy."""
        return {"policy": POLICY, "never_deletes": True, "defaults": dict(self.defaults),
                "windows": dict(WINDOWS), "status": dict(STATUS)}  # fmt: skip

    def usage(self, tenant: str) -> dict[str, Any]:
        metrics = {
            metric: {"limit": self.limit(tenant, metric), "used": self.used(tenant, metric),
                     "window": self._window(metric)[0]}
            for metric in FAIR_USE
        }  # fmt: skip
        return {"tenant": tenant, "usage": metrics}


__all__ = ["FAIR_USE", "LimitExceeded", "Limits", "POLICY"]
