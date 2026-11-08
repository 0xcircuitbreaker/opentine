"""Share tokens (0.46, ``caps.share``): scoped, expiring, revocable read access to one run.

A share token is ``tine_share_`` plus 32 random bytes in base64url. The server
keeps only its SHA-256 (a stolen ``shares.json`` grants nothing), the tenant, the
run it is bound to, the scope (``read``), who made it, when it expires and
whether it was revoked. A token that is unknown, expired, revoked or asked for an
object outside its run resolves to ``None``: every such case is the same 404 to
the caller, so a share route is never an oracle for which oids or runs exist.

Tokens are not signed and the server never signs as a user: a share grants read
access to bytes the browser re-verifies against the run's own signatures.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from opentine.kernel import parse_oid

PREFIX = "tine_share_"
SCOPES = ("read",)
MAX_TTL = 90 * 24 * 60 * 60
DEFAULT_TTL = 7 * 24 * 60 * 60
MAX_SHARES_PER_TENANT = 1000
_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def well_formed(token: str) -> bool:
    body = token[len(PREFIX) :] if token.startswith(PREFIX) else ""
    return len(body) == 43 and set(body) <= _TOKEN_CHARS


def public(record: dict[str, Any], now: float) -> dict[str, Any]:
    """A share as listed: never the token or its digest."""
    state = "revoked" if record["revoked"] else "expired" if record["expires"] <= now else "active"
    keys = ("id", "run", "scope", "created_by", "created", "expires")
    return {**{key: record[key] for key in keys}, "state": state}


class ShareStore:
    """Share records for every tenant, in one ``0600`` JSON file under the server state."""

    def __init__(self, path: str | Path, *, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self._lock = threading.Lock()

    def _load(self) -> list[dict[str, Any]]:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return []
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError("share store is corrupt")
        return data

    def _save(self, records: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".shares.")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(json.dumps(records, sort_keys=True).encode())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def create(
        self, tenant: str, run: str, subject: str, *, ttl: int = DEFAULT_TTL, scope: str = "read"
    ) -> tuple[str, dict[str, Any]]:
        if parse_oid(run)[0] != "run":
            raise ValueError("a share is bound to a run oid")
        if scope not in SCOPES:
            raise ValueError("unknown share scope")
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 60 <= ttl <= MAX_TTL:
            raise ValueError(f"ttl must be 60..{MAX_TTL} seconds")
        token = PREFIX + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        now = int(self.clock())
        record = {
            "id": secrets.token_hex(8),
            "digest": _digest(token),
            "tenant": tenant,
            "run": run,
            "scope": scope,
            "created_by": subject,
            "created": now,
            "expires": now + ttl,
            "revoked": False,
        }
        with self._lock:
            records = self._load()
            live = [r for r in records if r["tenant"] == tenant and not r["revoked"]]
            if len([r for r in live if r["expires"] > now]) >= MAX_SHARES_PER_TENANT:
                raise ValueError("too many active shares in this tenant")
            # Expired and revoked records age out after the longest TTL.
            records = [r for r in records if r["expires"] + MAX_TTL > now]
            records.append(record)
            self._save(records)
        return token, public(record, now)

    def list(self, tenant: str, run: str | None = None) -> list[dict[str, Any]]:
        now = self.clock()
        with self._lock:
            records = self._load()
        rows = [r for r in records if r["tenant"] == tenant and (run is None or r["run"] == run)]
        return [public(r, now) for r in sorted(rows, key=lambda r: (r["created"], r["id"]))]

    def revoke(self, tenant: str, share_id: str) -> dict[str, Any]:
        with self._lock:
            records = self._load()
            for record in records:
                if record["tenant"] == tenant and record["id"] == share_id:
                    record["revoked"] = True
                    self._save(records)
                    return public(record, self.clock())
        raise KeyError(share_id)

    def resolve(self, token: str) -> dict[str, Any] | None:
        """The live record *token* names, or ``None`` (unknown, expired, revoked)."""
        if not well_formed(token):
            return None
        digest = _digest(token)
        now = self.clock()
        with self._lock:
            records = self._load()
        found = None
        for record in records:  # no early exit: the scan costs the same either way
            if hmac.compare_digest(record["digest"], digest):
                found = record
        if found is None or found["revoked"] or found["expires"] <= now:
            return None
        return found


__all__ = ["DEFAULT_TTL", "MAX_TTL", "PREFIX", "SCOPES", "ShareStore", "public", "well_formed"]
