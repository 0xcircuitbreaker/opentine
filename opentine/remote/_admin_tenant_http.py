"""Per-tenant admin routes: rename, archive, members, invitations, settings, retention, holds.

A caller with no role in the tenant gets the uniform ``404``; a member whose
role is too weak gets ``403``. Reads need ``reader``; every change needs
``admin``. An archived tenant is read-only (data routes too, via
``MembershipAuthorization``) until an admin unarchives it; holds may still be
placed on it, since a hold only ever keeps more. Holds are the ``tine-holds/1``
file the object store already refuses deletes by (``<root>/.holds/<tenant>``).
"""

from __future__ import annotations

import math
from pathlib import Path
from urllib.parse import unquote

from opentine import _retention
from opentine.kernel import OID_RE
from opentine.remote._admin_http import Refused, audit, unregistered
from opentine.remote._admin_store import INVITE_TTL, Conflict, check_role, check_text, role_rank
from opentine.remote.backend import valid_tenant
from opentine.repository._holds import edit_holds, read_holds

SETTINGS = {"description": 1000, "homepage": 300, "default_ref": 200}


def _need(surface, caller, tenant: str, role: str) -> str:
    have = surface.role(caller, tenant)
    if have is None:
        raise KeyError(tenant)
    if role_rank(have) < role_rank(role):
        raise Refused("403 Forbidden", f"needs the {role} role", "tenant.forbidden")
    return have


def _row(surface, tenant: str, *, writable: bool = False) -> dict:
    row = surface.store.tenant(tenant)
    if row is None:
        raise KeyError(tenant)
    if writable and row["archived"]:
        raise Conflict("tenant is archived", "tenant.archived")
    return row


def tenant_route(app, surface, caller, tenant, resource, method, environ, sr):
    valid_tenant(tenant)
    ok, store = app._json_response, surface.store
    head, _, rest = resource.partition("/")
    read = method == "GET"
    role = _need(surface, caller, tenant, "reader" if read else "admin")

    def done(action: str, body, status="200 OK", **details):
        audit(app.service, caller, tenant, "admin." + action, details)
        return ok(sr, status, body)

    if head == "" and read:
        row = store.tenant(tenant)
        if row is None:  # a tenant only a bearer token names: not registered yet
            return ok(sr, "200 OK", unregistered(tenant, role))
        return ok(sr, "200 OK", store.public_tenant(tenant, row, role))
    if head == "" and method == "PATCH":
        _row(surface, tenant, writable=True)
        name = check_text(app._json(environ, "display_name").get("display_name"), "display_name")
        row = store.update_tenant(tenant, display_name=name)
        return done("tenant_rename", store.public_tenant(tenant, row, role))
    if head in ("archive", "unarchive") and method == "POST" and not rest:
        app._json(environ)
        _row(surface, tenant)
        row = store.update_tenant(tenant, archived=head == "archive")
        return done("tenant_" + head, store.public_tenant(tenant, row, role))
    if head == "members":
        return _members(app, surface, tenant, rest, method, environ, sr, done)
    if head == "invitations" and not rest and method in ("GET", "POST"):
        _row(surface, tenant, writable=not read)
        if read:
            return ok(sr, "200 OK", {"invitations": store.invitations(tenant)})
        request = app._json(environ, "role", "ttl_seconds")
        ttl = request.get("ttl_seconds", INVITE_TTL)
        if not isinstance(ttl, int) or isinstance(ttl, bool) or not 60 <= ttl <= INVITE_TTL:
            raise ValueError(f"ttl_seconds must be an integer from 60 to {INVITE_TTL}")
        made = store.invite(tenant, check_role(request.get("role", "reader")), caller.subject, ttl)
        return done("invitation_create", made, "201 Created", invitation=made["id"])
    if head == "invitations" and rest and method == "DELETE":
        store.revoke_invite(tenant, unquote(rest))
        return done("invitation_revoke", {"revoked": unquote(rest)}, invitation=unquote(rest))
    if head == "settings" and not rest:
        row = _row(surface, tenant, writable=not read)
        if method == "PATCH":
            row = store.update_tenant(tenant, settings=_settings(app, environ, row["settings"]))
        elif not read:
            raise KeyError(resource)
        body = {"settings": row["settings"], "limits": surface.limits()}
        return ok(sr, "200 OK", body) if read else done("settings_update", body)
    if head == "retention" and not rest:
        row = _row(surface, tenant, writable=not read)
        if method == "PUT":
            row = store.update_tenant(tenant, retention=_policy(app, environ))
        elif not read:
            raise KeyError(resource)
        body = {"policy": row["retention"], "server_deletes": False}
        return ok(sr, "200 OK", body) if read else done("retention_update", body)
    if head == "holds":
        if method == "DELETE" and store.tenant(tenant):  # releasing a hold is a change
            _row(surface, tenant, writable=True)
        return _holds(app, tenant, rest, method, environ, sr, done)
    raise KeyError(resource)


def _members(app, surface, tenant, rest, method, environ, sr, done):
    store = surface.store
    row = _row(surface, tenant, writable=method != "GET")
    if not rest and method == "GET":
        return app._json_response(sr, "200 OK", _member_list(row["members"]))
    subject = unquote(rest)
    check_text(subject, "subject")
    if rest and method == "PUT":
        role = check_role(app._json(environ, "role").get("role"))
        members = store.set_member(tenant, subject, role)
        return done("member_set", _member_list(members), subject=subject, role=role)
    if rest and method == "DELETE":
        members = store.set_member(tenant, subject, None)
        return done("member_remove", _member_list(members), subject=subject)
    raise KeyError(rest)


def _member_list(members: dict[str, str]) -> dict:
    return {"members": [{"subject": s, "role": r} for s, r in sorted(members.items())]}


def _settings(app, environ, current: dict) -> dict:
    request = app._json(environ, *SETTINGS)
    merged = dict(current)
    for key, value in request.items():
        if value is None:
            merged.pop(key, None)
            continue
        if not isinstance(value, str) or len(value) > SETTINGS[key]:
            raise ValueError(f"{key} must be a string of at most {SETTINGS[key]} characters")
        if any(ord(char) < 32 for char in value):
            raise ValueError(f"{key} contains control characters")
        text = value
        if key == "homepage" and text and not text.startswith("https://"):
            raise ValueError("homepage must be an https:// URL")
        merged[key] = text
    return merged


def _policy(app, environ) -> dict:
    request = app._json(environ, "keep_days", "refs", "status", "tier")
    try:
        policy = {"keep_days": _retention._days(request.get("keep_days", 14), "keep_days")}
        for name in ("refs", "status", "tier"):
            policy[name] = _retention._table(request, name)
    except _retention.RetentionError as exc:
        raise ValueError(str(exc)) from exc
    tables = [policy[name] for name in ("refs", "status", "tier")]
    values = [policy["keep_days"], *(v for table in tables for v in table.values())]
    if max(map(len, tables)) > 100 or not all(math.isfinite(v) for v in values):
        raise ValueError("retention takes at most 100 rules per table, in finite days")
    return policy


def _holds(app, tenant, rest, method, environ, sr, done):
    objects = app.service.objects
    root = getattr(objects, "holds_root", None) or getattr(objects, "root", None)
    if root is None:
        raise KeyError("holds")
    path = Path(root) / ".holds" / tenant
    if not rest and method == "GET":
        return app._json_response(sr, "200 OK", {"holds": read_holds(path)})
    if not rest and method == "POST":
        oid = app._json(environ, "oid").get("oid")
        if not isinstance(oid, str) or not OID_RE.fullmatch(oid):
            raise ValueError("oid must be a typed object id")
        if not objects.has(tenant, oid):
            raise KeyError(oid)
        row = {"oid": oid, "target": oid}
        rows = edit_holds(path, lambda old: [*(r for r in old if r != row), row])
        if callable(getattr(objects, "set_hold", None)):
            objects.set_hold(tenant, oid, True)
        return done("hold_add", {"holds": rows}, "201 Created", oid=oid)
    oid = unquote(rest)
    if rest and method == "DELETE":
        gone: list = []

        def change(old):
            gone.extend(r for r in old if r["oid"] == oid)
            return [r for r in old if r["oid"] != oid]

        rows = edit_holds(path, change)
        if not gone:
            raise KeyError(oid)
        if callable(getattr(objects, "set_hold", None)):
            objects.set_hold(tenant, oid, False)
        return done("hold_release", {"holds": rows}, oid=oid)
    raise KeyError(rest)


__all__ = ["tenant_route"]
