"""HTTP routes of the 0.52 admin surface: session, login, tenants (SPEC 8.27).

None of these routes carries signed data. Errors share one shape,
``{"error": text, "code": "area.reason"}`` (a uniform ``404`` stays
``{"error": "not found"}``): ``400`` a malformed request or a ceremony that
does not verify, ``401`` no valid session or token, ``403`` a member without
the role, ``404`` anything the caller may not see, ``409`` a state conflict,
``429`` a published limit (nothing is ever deleted to make room).
"""

from __future__ import annotations

from typing import Any

from opentine.remote._admin_store import Conflict, check_text
from opentine.remote._webauthn import WebAuthnError
from opentine.remote.backend import valid_tenant

_TENANT_RESOURCES = ("", "archive", "unarchive", "members", "invitations", "settings",
                     "retention", "holds")  # fmt: skip
_AUTH = "/v1/auth/"


class Refused(Exception):
    def __init__(self, status: str, message: str, code: str):
        super().__init__(message)
        self.status, self.code = status, code


def is_admin_path(path: str) -> bool:
    if path in ("/v1/session", "/v1/tenants", "/v1/invitations/accept"):
        return True
    if path.startswith(_AUTH):
        return True
    if path.startswith("/v1/tenants/"):
        _, _, resource = path[12:].partition("/")
        return resource.split("/", 1)[0] in _TENANT_RESOURCES
    return False


def early_route(app: Any, path: str, method: str, environ, sr):
    """Routes answered before the data routes' authentication: share links, the admin surface."""
    if path.startswith("/v1/share/"):  # 0.46: public share links, no bearer
        from opentine.remote._hosted_http import share_route

        return share_route(app, path[10:], method, environ, sr)
    return admin_route(app, path, method, environ, sr)


def admin_route(app: Any, path: str, method: str, environ, sr):
    """Answer an admin-surface request, or ``None`` when *path* is not one."""
    surface = getattr(app.service, "admin", None)
    if surface is None or not is_admin_path(path):
        return None
    client = environ.get("REMOTE_ADDR") or "unknown"
    wait = app.auth_throttle.retry_after(client)
    if wait:
        body = {"error": "too many failed authentications", "code": "auth.throttled"}
        return app._json_response(sr, "429 Too Many Requests", body, [("Retry-After", str(wait))])
    try:
        return _route(app, surface, path, method, environ, sr, client)
    except Refused as exc:
        return app._json_response(sr, exc.status, {"error": str(exc), "code": exc.code})
    except Conflict as exc:
        status = "429 Too Many Requests" if exc.code.endswith(".limit") else "409 Conflict"
        return app._json_response(sr, status, {"error": str(exc), "code": exc.code})
    except WebAuthnError as exc:
        app.auth_throttle.failed(client)
        body = {"error": str(exc), "code": "auth.passkey_invalid"}
        return app._json_response(sr, "400 Bad Request", body)
    except KeyError:
        return app._json_response(sr, "404 Not Found", {"error": "not found"})
    except ValueError as exc:
        body = {"error": str(exc) or "invalid request", "code": "request.invalid"}
        return app._json_response(sr, "400 Bad Request", body)


def _caller(app, surface, environ, client):
    try:
        caller = surface.caller(app.service, app._headers(environ))
    except PermissionError:
        app.auth_throttle.failed(client)
        raise Refused("401 Unauthorized", "authentication failed", "auth.required") from None
    app.auth_throttle.succeeded(client)
    return caller


def _route(app, surface, path, method, environ, sr, client):
    ok = app._json_response
    if path.startswith(_AUTH):
        return _auth(app, surface, path[len(_AUTH) :], method, environ, sr, client)
    caller = _caller(app, surface, environ, client)
    if path == "/v1/session":
        if method == "GET":
            return ok(sr, "200 OK", whoami(surface, caller))
        if method == "DELETE":
            ended = bool(caller.token) and surface.store.close_session(caller.token)
            return ok(sr, "200 OK", {"ended": ended})
    elif path == "/v1/tenants":
        if method == "GET":
            return ok(sr, "200 OK", {"tenants": whoami(surface, caller)["tenants"]})
        if method == "POST":
            return ok(sr, "201 Created", _create(app, surface, caller, environ))
    elif path == "/v1/invitations/accept" and method == "POST":
        token = app._json(environ, "token").get("token")
        if not isinstance(token, str) or not caller.token:
            raise ValueError("accepting an invitation needs a session and its token")
        return ok(sr, "200 OK", surface.store.accept(token, caller.subject))
    else:
        from opentine.remote._admin_tenant_http import tenant_route

        tenant, _, resource = path[12:].partition("/")
        return tenant_route(app, surface, caller, tenant, resource, method, environ, sr)
    raise KeyError(path)


def whoami(surface, caller) -> dict[str, Any]:
    tenants = {row["name"]: row for row in surface.store.tenants_of(caller.subject)}
    identity = caller.identity
    if identity is not None and identity.tenant not in tenants:
        row = surface.store.tenant(identity.tenant)
        role = surface.role(caller, identity.tenant)
        if row is not None:
            tenants[identity.tenant] = surface.store.public_tenant(identity.tenant, row, role)
        else:
            tenants[identity.tenant] = unregistered(identity.tenant, role)
    return {"subject": caller.subject, "method": caller.method, "expires_at": caller.expires_at,
            "tenants": [tenants[name] for name in sorted(tenants)]}  # fmt: skip


def unregistered(tenant: str, role: str | None) -> dict[str, Any]:
    """A tenant only a bearer token names: served, but not registered on the admin surface."""
    return {"name": tenant, "display_name": tenant, "archived": False, "created_at": None,
            "role": role}  # fmt: skip


def _create(app, surface, caller, environ):
    request = app._json(environ, "name", "display_name")
    name = valid_tenant(check_text(request.get("name"), "name"))
    display = check_text(request.get("display_name", name), "display_name")
    own_token_tenant = caller.identity is not None and caller.identity.tenant == name
    if not (surface.open_signup or (own_token_tenant and surface.role(caller, name) == "admin")):
        raise Refused("403 Forbidden", "tenant creation is not open on this server",
                      "tenant.signup_closed")  # fmt: skip
    service = app.service
    in_use = service.index.list_refs(name) or service.objects.list(name, limit=1)
    if in_use and not own_token_tenant:
        raise Conflict("tenant already exists", "tenant.exists")
    created = surface.store.create_tenant(name, display, caller.subject)
    audit(service, caller, name, "admin.tenant_create", {})
    return created


def _auth(app, surface, rest, method, environ, sr, client):
    ok = app._json_response
    if method != "POST":
        raise KeyError(rest)
    if rest == "dev/login" and surface.dev is not None:
        subject = surface.dev.login(app._json(environ, "subject"))
        return ok(sr, "201 Created", surface.store.open_session(subject, "dev"))
    passkey = surface.passkey
    if passkey is None or not rest.startswith("passkey/"):
        raise KeyError(rest)
    rest = rest[8:]
    if rest == "assertion/options":
        app._json(environ)
        return ok(sr, "200 OK", passkey.assertion_options())
    if rest == "assertion":
        fields = ("challenge", "credential_id", "clientDataJSON", "authenticatorData", "signature")
        subject = passkey.login(app._json(environ, *fields, "userHandle"))
        return ok(sr, "201 Created", surface.store.open_session(subject, "passkey"))
    if rest in ("registration/options", "registration"):
        from opentine.remote._admin_signup import registration

        return registration(app, surface, rest, environ, sr, client)
    raise KeyError(rest)


def audit(service, caller, tenant: str, action: str, details: dict[str, Any]) -> None:
    import uuid
    from datetime import UTC, datetime

    from opentine.remote.interfaces import AuditEvent

    event = AuditEvent(str(uuid.uuid4()), datetime.now(UTC).isoformat(), tenant, caller.subject,
                       action, "ok", details)  # fmt: skip
    service.audit.append(event)


__all__ = [
    "Refused",
    "admin_route",
    "early_route",
    "unregistered",
    "audit",
    "is_admin_path",
    "whoami",
]
