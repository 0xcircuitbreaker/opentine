"""Scoped, expiring, revocable API tokens for ``tine serve`` (0.52).

A token is ``tine_pat_<id>_<secret>`` (``tine_ci_`` when the CI OIDC exchange
issued it). Only the SHA-256 digest of the secret is stored, in
``<root>/auth.sqlite3``, and a presented secret is compared with
:func:`hmac.compare_digest`. Every authentication reads the row again, so a
revocation or an expiry takes effect on the next request of a running server.
What the token may reach is :mod:`_token_scope`. A token never deletes
anything and is never ``admin``; a revoked row is kept (``revoked_at``) for
the audit trail, and only expired CI tokens past a day are pruned.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from opentine._utc import rfc3339_utc
from opentine.remote._token_scope import ACCESS, SCOPE_CLAIM, check_namespaces
from opentine.remote.interfaces import Identity
from opentine.remote.security import AuthenticationError

PREFIXES = {"pat": "tine_pat_", "ci": "tine_ci_"}
_TOKEN = re.compile(r"^tine_(pat|ci)_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$")
DEFAULT_TTL = 90 * 24 * 3600
MAX_TTL = 366 * 24 * 3600
MAX_CI_TTL = 3600
#: Live (unrevoked, unexpired) tokens one tenant may hold.
MAX_LIVE_PER_TENANT = 1000
_SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, digest BLOB NOT NULL, tenant TEXT NOT NULL,
  access TEXT NOT NULL, refs TEXT NOT NULL, label TEXT NOT NULL, subject TEXT NOT NULL,
  created REAL NOT NULL, expires REAL NOT NULL, revoked REAL);
CREATE TABLE IF NOT EXISTS seen_jti (issuer TEXT, jti TEXT, until REAL,
  PRIMARY KEY (issuer, jti));
"""


def iso(seconds: float) -> str:
    return rfc3339_utc(int(seconds))


def parse_ttl(text: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]{0,6})([smhd])", text or "")
    if not match:
        raise ValueError("a TTL is a number and a unit: 900s, 12h, 30d")
    return int(match[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]


def _digest(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("ascii")).digest()


class TokenStore:
    def __init__(self, path: str | Path, *, now: Callable[[], float] = time.time):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.now = now
        self._lock = threading.Lock()
        with self._db() as db:
            db.executescript(_SCHEMA)

    @classmethod
    def at(cls, root: str | Path, **kwargs: Any) -> TokenStore:
        return cls(Path(root) / "auth.sqlite3", **kwargs)

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    def mint(
        self,
        tenant: str,
        access: str,
        refs: list[str],
        *,
        ttl: int = DEFAULT_TTL,
        label: str = "",
        kind: str = "pat",
        subject: str = "",
    ) -> tuple[str, dict[str, Any]]:
        """``(the secret token, shown once; its public record)``."""
        from opentine.remote.backend import valid_tenant

        valid_tenant(tenant)
        if access not in ACCESS:
            raise ValueError("access is read or write")
        limit = MAX_CI_TTL if kind == "ci" else MAX_TTL
        if kind not in PREFIXES or isinstance(ttl, bool) or not 1 <= int(ttl) <= limit:
            raise ValueError(f"a {kind} token lives 1 to {limit} seconds")
        if len(label) > 128:
            raise ValueError("a token label is at most 128 characters")
        refs = check_namespaces(refs)
        token_id, secret = secrets.token_hex(8), secrets.token_urlsafe(32)
        now = self.now()
        row = (token_id, kind, _digest(secret), tenant, access, json.dumps(refs), label)
        row += (subject or f"token:{token_id}", now, now + int(ttl))
        with self._lock, self._db() as db:
            db.execute("DELETE FROM tokens WHERE kind = 'ci' AND expires < ?", (now - 86400,))
            db.execute("DELETE FROM seen_jti WHERE until < ?", (now,))
            live = db.execute(
                "SELECT COUNT(*) FROM tokens WHERE tenant = ? AND revoked IS NULL AND expires > ?",
                (tenant, now),
            ).fetchone()[0]
            if live >= MAX_LIVE_PER_TENANT:
                raise ValueError(f"tenant {tenant} already holds {live} live tokens")
            db.execute("INSERT INTO tokens VALUES (?,?,?,?,?,?,?,?,?,?,NULL)", row)
        return f"{PREFIXES[kind]}{token_id}_{secret}", self.get(token_id)

    def first_use(self, issuer: str, jti: str, until: float) -> bool:
        """Record a CI token id; ``False`` when it was already exchanged."""
        with self._lock, self._db() as db:
            try:
                db.execute("INSERT INTO seen_jti VALUES (?,?,?)", (issuer, jti, until))
            except sqlite3.IntegrityError:
                return False
        return True

    def _record(self, row: sqlite3.Row) -> dict[str, Any]:
        now = self.now()
        state = "revoked" if row["revoked"] else "expired" if row["expires"] <= now else "active"
        record = {"id": row["id"], "kind": row["kind"], "tenant": row["tenant"]}
        record |= {"access": row["access"], "refs": json.loads(row["refs"]), "state": state}
        record |= {"created_at": iso(row["created"]), "expires_at": iso(row["expires"])}
        if row["label"]:
            record["label"] = row["label"]
        if row["revoked"]:
            record["revoked_at"] = iso(row["revoked"])
        return record

    def get(self, token_id: str) -> dict[str, Any]:
        with self._db() as db:
            row = db.execute("SELECT * FROM tokens WHERE id = ?", (token_id,)).fetchone()
        if row is None:
            raise KeyError(token_id)
        return self._record(row)

    def list(self, tenant: str | None = None) -> list[dict[str, Any]]:
        query, args = "SELECT * FROM tokens", ()
        if tenant is not None:
            query, args = query + " WHERE tenant = ?", (tenant,)
        with self._db() as db:
            rows = db.execute(query + " ORDER BY created, id", args).fetchall()
        return [self._record(row) for row in rows]

    def revoke(self, token_id: str, tenant: str | None = None) -> dict[str, Any]:
        """Revoke (idempotent); a token of another *tenant* is ``KeyError`` like none."""
        with self._lock, self._db() as db:
            row = db.execute("SELECT tenant FROM tokens WHERE id = ?", (token_id,)).fetchone()
            if row is None or (tenant is not None and row["tenant"] != tenant):
                raise KeyError(token_id)
            db.execute(
                "UPDATE tokens SET revoked = ? WHERE id = ? AND revoked IS NULL",
                (self.now(), token_id),
            )
        return self.get(token_id)

    def identity(self, presented: str) -> Identity | None:
        """The identity of a token of this store; ``None`` when it is not one."""
        match = _TOKEN.fullmatch(presented)
        if not match:
            return None
        with self._db() as db:
            row = db.execute("SELECT * FROM tokens WHERE id = ?", (match[2],)).fetchone()
        if row is None:
            return None
        valid = hmac.compare_digest(_digest(match[3]), row["digest"]) and row["kind"] == match[1]
        if not valid or row["revoked"] or row["expires"] <= self.now():
            raise AuthenticationError("invalid, expired or revoked token")
        scope = {"token": row["id"], "access": row["access"], "refs": json.loads(row["refs"])}
        role = "writer" if row["access"] == "write" else "reader"
        return Identity(row["subject"], row["tenant"], (role,), {SCOPE_CLAIM: scope})


class TokenIdentityProvider:
    """Store tokens first; any other bearer goes to the operator's provider."""

    def __init__(self, store: TokenStore, fallback: Any):
        self.store = store
        self.fallback = fallback

    def authenticate(self, headers: dict[str, str]) -> Identity:
        authorization = headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            found = self.store.identity(authorization[7:].strip())
            if found is not None:
                return found
        return self.fallback.authenticate(headers)


__all__ = ["TokenIdentityProvider", "TokenStore", "iso", "parse_ttl"]
