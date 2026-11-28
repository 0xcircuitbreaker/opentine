"""The 0.52 admin surface's wiring: who is calling, and what a session may do elsewhere.

:class:`AdminSurface` hangs off ``RemoteService.admin``. A caller is either a
session (``Authorization: Bearer tine_sess_...``, opened by an authenticator)
or anyone the server's existing identity provider accepts (static tokens,
OIDC). :class:`SessionIdentities` and :class:`MembershipAuthorization` wrap the
existing provider and policy so a session reaches the data routes too, with
the role its tenant membership grants, and so an archived tenant is read-only
for everyone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from opentine.remote._admin_store import SESSION_PREFIX, AdminStore, role_rank
from opentine.remote._authn import DevAuthenticator, PasskeyAuthenticator
from opentine.remote._token_roles import role as token_role
from opentine.remote._token_scope import namespaces
from opentine.remote.interfaces import Identity

#: Actions an archived tenant still allows.
READ_ACTIONS = frozenset({"capabilities", "fetch", "negotiate", "read_ref", "search", "audit"})
SESSION_TENANT = "~session"  # never a valid tenant name: a session names none


def bearer(headers: dict[str, str]) -> str:
    value = headers.get("authorization", "")
    return value[7:].strip() if value.lower().startswith("bearer ") else ""


@dataclass(frozen=True)
class Caller:
    subject: str
    method: str  # "session:<authenticator>" or "bearer"
    token: str = ""
    identity: Identity | None = None
    expires_at: int | None = None


class AdminSurface:
    def __init__(
        self,
        store: AdminStore,
        *,
        passkey: PasskeyAuthenticator | None = None,
        dev_login: bool = False,
        open_signup: bool = False,
    ):
        self.store = store
        self.passkey = passkey
        self.dev = DevAuthenticator() if dev_login else None
        #: Whether any session may create a tenant (hosted: yes; tine serve: --open-signup).
        self.open_signup = open_signup

    def capabilities(self) -> dict[str, Any]:
        authenticators = {a.name: a.capabilities() for a in (self.passkey, self.dev) if a}
        return {
            "session": {"path": "/v1/session", "authenticators": authenticators,
                        "provider_signin": "identity-linking-only"},
            "tenancy": {"path": "/v1/tenants", "open_signup": self.open_signup,
                        "roles": ["reader", "writer", "admin"], "limits": self.limits()},
        }  # fmt: skip

    @staticmethod
    def limits() -> dict[str, int]:
        from opentine.remote import _admin_store as s

        return {"tenants_per_subject": s.MAX_TENANTS_PER_SUBJECT, "members": s.MAX_MEMBERS,
                "open_invitations": s.MAX_INVITES, "session_seconds": s.SESSION_TTL}  # fmt: skip

    def caller(self, service: Any, headers: dict[str, str]) -> Caller:
        token = bearer(headers)
        if token.startswith(SESSION_PREFIX):
            row = self.store.session(token)
            if row is None:
                raise PermissionError("session expired or ended")
            return Caller(row["subject"], "session:" + row["method"], token,
                          expires_at=int(row["expires"]))  # fmt: skip
        identity = service.authenticate(headers)
        return Caller(identity.subject, "bearer", identity=identity)

    def role(self, caller: Caller, tenant: str) -> str | None:
        """The caller's strongest role in *tenant*: membership, or a bearer token's own roles."""
        best = self.store.role(tenant, caller.subject)
        identity = caller.identity
        # A namespace-limited scoped token (SPEC 8.28) reaches no admin route.
        # A role token (0.90, ``_token_roles``) reaches none either: its role is its whole grant.
        bearer = identity is not None and identity.tenant == tenant
        if bearer and namespaces(identity) is None and token_role(identity) is None:
            for role in identity.roles:
                if role_rank(role) > role_rank(best):
                    best = role
        return best


class SessionIdentities:
    """The server's identity provider, plus admin-surface sessions."""

    def __init__(self, inner: Any, store: AdminStore):
        self.inner, self.store = inner, store

    def authenticate(self, headers: dict[str, str]) -> Identity:
        token = bearer(headers)
        if not token.startswith(SESSION_PREFIX):
            return self.inner.authenticate(headers)
        row = self.store.session(token)
        if row is None:
            raise PermissionError("session expired or ended")
        return Identity(row["subject"], SESSION_TENANT, ("session",), {"opentine_session": True})


class MembershipAuthorization:
    """The server's policy, with session roles from membership and archived tenants read-only."""

    def __init__(self, inner: Any, store: AdminStore):
        self.inner, self.store = inner, store

    def authorize(self, identity: Identity, action: str, tenant: str) -> bool:
        row = self.store.tenant(tenant)
        if row and row["archived"] and action not in READ_ACTIONS:
            return False
        if identity.claims.get("opentine_session") is True:
            role = row["members"].get(identity.subject) if row else None
            if role is None:
                return False
            identity = Identity(identity.subject, tenant, (role,))
        return bool(self.inner.authorize(identity, action, tenant))


def attach_admin(
    service: Any, state: Any, *, passkey_rp_id: str | None = None,
    passkey_origin: str | None = None, dev_login: bool = False, open_signup: bool = False,
) -> AdminSurface:  # fmt: skip
    """Give *service* the admin surface; sessions then reach the data routes too."""
    store = AdminStore(state)
    passkey = None
    if passkey_rp_id or passkey_origin:
        rp_id, origin = passkey_rp_id or "", passkey_origin or ""
        passkey = PasskeyAuthenticator(store, rp_id=rp_id, origin=origin)
    surface = AdminSurface(store, passkey=passkey, dev_login=dev_login, open_signup=open_signup)
    service.identities = SessionIdentities(service.identities, store)
    service.authorization = MembershipAuthorization(service.authorization, store)
    service.admin = surface
    return surface


def add_admin_surface_arguments(parser: Any) -> None:
    parser.add_argument("--passkey-rp-id", help="Enable passkey login for this WebAuthn RP id")
    parser.add_argument("--passkey-origin", help="The https:// origin passkey ceremonies run on")
    parser.add_argument(
        "--dev-login", action="store_true",
        help="Development only (needs --insecure-dev): sign in as any subject with no proof",
    )  # fmt: skip
    parser.add_argument(
        "--open-signup", action="store_true", help="Let any signed-in subject create tenants"
    )


def admin_options(args: Any) -> dict[str, Any]:
    if args.dev_login and not args.insecure_dev:
        raise SystemExit("--dev-login proves nothing: it is only allowed with --insecure-dev")
    if bool(args.passkey_rp_id) != bool(args.passkey_origin):
        raise SystemExit("--passkey-rp-id and --passkey-origin go together")
    return {"passkey_rp_id": args.passkey_rp_id, "passkey_origin": args.passkey_origin,
            "dev_login": args.dev_login, "open_signup": args.open_signup}  # fmt: skip


__all__ = [
    "AdminSurface",
    "add_admin_surface_arguments",
    "admin_options",
    "attach_admin",
    "Caller",
    "MembershipAuthorization",
    "SessionIdentities",
]
