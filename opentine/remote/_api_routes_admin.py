"""The 0.52 admin surface's rows of the v1 route table (tag ``admin``; SPEC 8.27).

Session, login and tenant management for the hosted web app (Tineyard maps
its ``/api/*`` onto these) and for ``tine serve`` alike (self-host parity).
Rows are plain tuples of ``_api_routes.Route`` fields (that module builds
them). No route here carries signed data, and the server never signs as a
user: a passkey's private key stays in the user's authenticator. ``permission``
names the admin-surface check: ``session`` (any signed-in caller),
``tenant_read`` (any role in the tenant), ``tenant_admin``, or ``None``
(public: the login ceremonies).
"""

from __future__ import annotations

T = "/tenants/{tenant}"
_AUTH = (("401", "Error"), ("429", "Error"))
_ERR = (("400", "Error"), ("401", "Error"), ("403", "Error"), ("404", "Error"), ("409", "Error"),
        ("429", "Error"))  # fmt: skip
_PUBLIC = (("400", "Error"), ("404", "Error"), ("429", "Error"))


def _r(method, path, op, summary, cap, permission, request, ok):
    errors = _PUBLIC if permission is None else _AUTH if permission == "session" else _ERR
    if permission == "session" and request:
        errors = _ERR
    return (method, path, op, summary, cap, "stable", permission, request, (ok, *errors), "admin")


S, Y = "session", "tenancy"
ADMIN_ROUTES: tuple[tuple, ...] = (  # Route fields, in order
    _r("GET", "/session", "getSession", "Who is calling, and their tenants", S, "session", None,
       ("200", "Session")),
    _r("DELETE", "/session", "endSession", "Log out: end this session", S, "session", None,
       ("200", "SessionEnded")),
    _r("POST", "/auth/dev/login", "devLogin", "Development login with no proof (opt-in)", S,
       None, "DevLogin", ("201", "SessionOpened")),
    _r("POST", "/auth/passkey/registration/options", "passkeyRegistrationOptions",
       "WebAuthn creation options (signed in, or with an invitation)", S, None,
       "PasskeyRegistrationStart", ("200", "PasskeyCreationOptions")),
    _r("POST", "/auth/passkey/registration", "registerPasskey",
       "Store a passkey's public key (never a private key)", S, None, "PasskeyRegistration",
       ("201", "PasskeyRegistered")),
    _r("POST", "/auth/passkey/assertion/options", "passkeyAssertionOptions",
       "WebAuthn request options for login", S, None, None, ("200", "PasskeyRequestOptions")),
    _r("POST", "/auth/passkey/assertion", "passkeyLogin", "Verify a passkey assertion; a session",
       S, None, "PasskeyAssertion", ("201", "SessionOpened")),
    _r("GET", "/tenants", "listTenants", "The caller's tenants and roles", Y, "session", None,
       ("200", "TenantList")),
    _r("POST", "/tenants", "createTenant", "Create (or register) a tenant; the caller is admin",
       Y, "session", "TenantCreate", ("201", "Tenant")),
    _r("POST", "/invitations/accept", "acceptInvitation", "Join a tenant with an invitation",
       Y, "session", "InvitationAccept", ("200", "Tenant")),
    _r("GET", T, "getTenant", "The tenant's name, display name and state", Y, "tenant_read",
       None, ("200", "Tenant")),
    _r("PATCH", T, "renameTenant", "Change the display name (the tenant id never changes)", Y,
       "tenant_admin", "TenantRename", ("200", "Tenant")),
    _r("POST", T + "/archive", "archiveTenant", "Make the tenant read-only (nothing is deleted)",
       Y, "tenant_admin", None, ("200", "Tenant")),
    _r("POST", T + "/unarchive", "unarchiveTenant", "Make an archived tenant writable again", Y,
       "tenant_admin", None, ("200", "Tenant")),
    _r("GET", T + "/members", "listMembers", "Members and their roles", Y, "tenant_read", None,
       ("200", "MemberList")),
    _r("PUT", T + "/members/{subject}", "setMember", "Add a member or change a role", Y,
       "tenant_admin", "MemberRole", ("200", "MemberList")),
    _r("DELETE", T + "/members/{subject}", "removeMember", "Remove a member (never the last admin)",
       Y, "tenant_admin", None, ("200", "MemberList")),
    _r("GET", T + "/invitations", "listInvitations", "Open invitations (never a token)", Y,
       "tenant_admin", None, ("200", "InvitationList")),
    _r("POST", T + "/invitations", "createInvitation", "A single-use invitation token", Y,
       "tenant_admin", "InvitationCreate", ("201", "InvitationCreated")),
    _r("DELETE", T + "/invitations/{invitation_id}", "revokeInvitation", "Revoke an invitation",
       Y, "tenant_admin", None, ("200", "InvitationRevoked")),
    _r("GET", T + "/settings", "getSettings", "Tenant settings and the published limits", Y,
       "tenant_read", None, ("200", "TenantSettings")),
    _r("PATCH", T + "/settings", "updateSettings", "Merge settings (null removes a key)", Y,
       "tenant_admin", "SettingsUpdate", ("200", "TenantSettings")),
    _r("GET", T + "/retention", "getRetention", "The stored retention policy", Y, "tenant_read",
       None, ("200", "Retention")),
    _r("PUT", T + "/retention", "setRetention", "Store a retention policy (the server never "
       "deletes on its own)", Y, "tenant_admin", "RetentionPolicy", ("200", "Retention")),
    _r("GET", T + "/holds", "listHolds", "Held objects (tine-holds/1 rows)", Y, "tenant_read",
       None, ("200", "HoldList")),
    _r("POST", T + "/holds", "addHold", "Hold a stored object: every delete refuses it", Y,
       "tenant_admin", "HoldRequest", ("201", "HoldList")),
    _r("DELETE", T + "/holds/{oid}", "releaseHold", "Release a hold", Y, "tenant_admin", None,
       ("200", "HoldList")),
)  # fmt: skip

__all__ = ["ADMIN_ROUTES"]
