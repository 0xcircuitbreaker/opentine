"""Server-side state of the 0.52 admin surface: sessions, passkeys, tenants, members.

Nothing here is signed data and nothing here signs: the server holds passkey
*public* keys only (the private half never leaves the user's authenticator),
session and invitation secrets only as SHA-256 digests, and tenant metadata
(display name, archived flag, settings, retention). Runs, refs and holds stay
where they always were. The state is one JSON file under the server's state
directory, rewritten atomically under a lock; it is server-internal, not a
wire format.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from opentine.remote.backend import valid_tenant
from opentine.repository._paths import atomic_bytes

ROLES = ("reader", "writer", "admin")
SESSION_PREFIX = "tine_sess_"
INVITE_PREFIX = "tine_invite_"
SESSION_TTL = 7 * 24 * 3600
INVITE_TTL = 7 * 24 * 3600
MAX_TENANTS_PER_SUBJECT = 100
MAX_MEMBERS = 1000
MAX_INVITES = 200
MAX_TEXT = 200


class Conflict(Exception):
    """The request is well formed but the state refuses it (HTTP 409)."""

    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


def digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def role_rank(role: str | None) -> int:
    return ROLES.index(role) + 1 if role in ROLES else 0


def check_text(value: Any, what: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not empty) or len(value) > MAX_TEXT:
        raise ValueError(f"{what} must be a string of at most {MAX_TEXT} characters")
    if any(ord(char) < 32 for char in value):
        raise ValueError(f"{what} contains control characters")
    return value


def check_role(value: Any) -> str:
    if value not in ROLES:
        raise ValueError("role must be reader, writer or admin")
    return value


class AdminStore:
    def __init__(self, root: str | Path, *, clock=time.time):
        self.path = Path(root) / "admin" / "state.json"
        self.clock = clock
        self._lock = threading.RLock()

    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_bytes())
        except FileNotFoundError:
            data = {}
        for key in ("sessions", "credentials", "tenants", "invitations"):
            data.setdefault(key, {})
        return data

    @contextmanager
    def edit(self):
        with self._lock:
            state = self._read()
            yield state
            self.path.parent.mkdir(parents=True, exist_ok=True)
            atomic_bytes(self.path, json.dumps(state, sort_keys=True).encode() + b"\n")

    def read(self) -> dict[str, Any]:
        with self._lock:
            return self._read()

    # -- sessions -------------------------------------------------------------
    def open_session(self, subject: str, method: str) -> dict[str, Any]:
        token = SESSION_PREFIX + secrets.token_urlsafe(32)
        now = self.clock()
        row = {"subject": subject, "method": method, "created": now, "expires": now + SESSION_TTL}
        with self.edit() as state:
            state["sessions"] = {k: v for k, v in state["sessions"].items() if v["expires"] > now}
            state["sessions"][digest(token)] = row
        return {"token": token, **self._public_session(row)}

    def session(self, token: str) -> dict[str, Any] | None:
        row = self.read()["sessions"].get(digest(token))
        if row is None or row["expires"] <= self.clock():
            return None
        return row

    def close_session(self, token: str) -> bool:
        with self.edit() as state:
            return state["sessions"].pop(digest(token), None) is not None

    @staticmethod
    def _public_session(row: dict[str, Any]) -> dict[str, Any]:
        return {"subject": row["subject"], "method": row["method"],
                "expires_at": int(row["expires"])}  # fmt: skip

    # -- passkey credentials (public keys only) ---------------------------------
    def add_credential(self, credential_id: str, row: dict[str, Any]) -> None:
        with self.edit() as state:
            if credential_id in state["credentials"]:
                raise Conflict("credential is already registered", "auth.credential_exists")
            state["credentials"][credential_id] = row

    def credential(self, credential_id: str) -> dict[str, Any] | None:
        return self.read()["credentials"].get(credential_id)

    def bump_counter(self, credential_id: str, counter: int) -> None:
        with self.edit() as state:
            state["credentials"][credential_id]["sign_count"] = counter

    # -- tenants ----------------------------------------------------------------
    def tenant(self, name: str) -> dict[str, Any] | None:
        return self.read()["tenants"].get(name)

    def role(self, name: str, subject: str) -> str | None:
        row = self.tenant(name)
        return row["members"].get(subject) if row else None

    def tenants_of(self, subject: str) -> list[dict[str, Any]]:
        rows = self.read()["tenants"]
        return [
            self.public_tenant(name, row, row["members"][subject])
            for name, row in sorted(rows.items())
            if subject in row["members"]
        ]

    @staticmethod
    def public_tenant(name: str, row: dict[str, Any], role: str | None) -> dict[str, Any]:
        return {"name": name, "display_name": row["display_name"], "archived": row["archived"],
                "created_at": int(row["created"]), "role": role}  # fmt: skip

    def create_tenant(self, name: str, display_name: str, owner: str) -> dict[str, Any]:
        valid_tenant(name)
        with self.edit() as state:
            if name in state["tenants"]:
                raise Conflict("tenant already exists", "tenant.exists")
            owned = sum(owner in row["members"] for row in state["tenants"].values())
            if owned >= MAX_TENANTS_PER_SUBJECT:
                raise Conflict("too many tenants for this subject", "tenant.limit")
            row = {"display_name": display_name, "archived": False, "created": self.clock(),
                   "members": {owner: "admin"}, "settings": {}, "retention": None}  # fmt: skip
            state["tenants"][name] = row
        return self.public_tenant(name, row, "admin")

    def update_tenant(self, name: str, **changes: Any) -> dict[str, Any]:
        with self.edit() as state:
            row = state["tenants"].get(name)
            if row is None:
                raise KeyError(name)
            row.update(changes)
        return row

    def set_member(self, name: str, subject: str, role: str | None) -> dict[str, str]:
        with self.edit() as state:
            row = state["tenants"].get(name)
            if row is None:
                raise KeyError(name)
            members = dict(row["members"])
            if role is None:
                if members.pop(subject, None) is None:
                    raise KeyError(subject)
            else:
                if subject not in members and len(members) >= MAX_MEMBERS:
                    raise Conflict("tenant has too many members", "member.limit")
                members[subject] = role
            if "admin" not in members.values():
                raise Conflict("a tenant keeps at least one admin", "member.last_admin")
            row["members"] = members
        return members

    # -- invitations --------------------------------------------------------------
    def invite(self, name: str, role: str, inviter: str, ttl: float) -> dict[str, Any]:
        token = INVITE_PREFIX + secrets.token_urlsafe(32)
        now = self.clock()
        invite_id = "inv_" + secrets.token_hex(8)
        row = {"id": invite_id, "tenant": name, "role": role, "invited_by": inviter,
               "expires": now + ttl, "digest": digest(token)}  # fmt: skip
        with self.edit() as state:
            live = {k: v for k, v in state["invitations"].items() if v["expires"] > now}
            if sum(v["tenant"] == name for v in live.values()) >= MAX_INVITES:
                raise Conflict("tenant has too many open invitations", "invitation.limit")
            live[invite_id] = row
            state["invitations"] = live
        return {"token": token, **self.public_invite(row)}

    @staticmethod
    def public_invite(row: dict[str, Any]) -> dict[str, Any]:
        return {"id": row["id"], "tenant": row["tenant"], "role": row["role"],
                "invited_by": row["invited_by"], "expires_at": int(row["expires"])}  # fmt: skip

    def invitations(self, name: str) -> list[dict[str, Any]]:
        now = self.clock()
        rows = self.read()["invitations"].values()
        return sorted(
            (self.public_invite(r) for r in rows if r["tenant"] == name and r["expires"] > now),
            key=lambda r: r["id"],
        )

    def revoke_invite(self, name: str, invite_id: str) -> None:
        with self.edit() as state:
            row = state["invitations"].get(invite_id)
            if row is None or row["tenant"] != name:
                raise KeyError(invite_id)
            del state["invitations"][invite_id]

    def accept(self, token: str, subject: str) -> dict[str, Any]:
        wanted, now = digest(token), self.clock()
        with self.edit() as state:
            found = [
                key
                for key, row in state["invitations"].items()
                if secrets.compare_digest(row["digest"], wanted) and row["expires"] > now
            ]
            if not found:
                raise KeyError("invitation")
            row = state["invitations"].pop(found[0])
            tenant = state["tenants"].get(row["tenant"])
            if tenant is None or tenant["archived"]:
                raise KeyError("invitation")
            members = tenant["members"]
            if role_rank(row["role"]) > role_rank(members.get(subject)):
                members[subject] = row["role"]
        return self.public_tenant(row["tenant"], tenant, members[subject])


__all__ = ["AdminStore", "Conflict", "ROLES", "SESSION_PREFIX", "check_role", "check_text"]
