"""What a scoped API token may reach (0.52, ``caps.scoped_tokens``).

A token minted by ``tine serve token mint`` or issued by the CI OIDC exchange
(``_ci_exchange``) authenticates as an :class:`Identity` of exactly one tenant
whose ``roles`` are ``("reader",)`` or ``("writer",)``, never ``admin``, and
whose claims carry ``opentine_scope``: ``{"token", "access", "refs"}``.

``refs`` lists ref namespaces: an exact ref (``heads/main``) or a prefix ending
in ``/`` (``heads/ci/``). ``["*"]`` is the whole tenant, and such a token is
an ordinary reader or writer. Any other list makes the token **namespace
limited**, and then only these routes answer it, each checked against the
namespaces:

- ``GET refs`` lists only the refs inside them;
- ``POST negotiate`` and ``POST fetch`` serve only closures whose every
  ``want`` is the target of such a ref (anything else is the uniform 404);
- with ``write`` access, ``PUT refs/<name>`` and ``POST ref-txn`` move only
  refs inside them, and packs may be uploaded. Objects are content-addressed:
  one is readable only through a visible ref, but a writer that knows an id
  can point its own ref at it, so namespaces confine refs, not object ids.

Every other route (events, search, object reads, reviews, coordination, shares,
webhooks, tombstones...) authorizes a tenant-wide action, which a namespace
limited token is never granted. The scoped routes ask for ``ACTION@scoped``
(:func:`scoped_action`); :class:`ScopedPolicy` grants that only within the
token's access and passes the plain action on to the operator's policy, which
still decides by role and tenant. A malformed ``opentine_scope`` claim fails
closed: it limits the identity to no namespace at all.
"""

from __future__ import annotations

from typing import Any

from opentine.remote._request_audit import AuthorizationDenied

SCOPE_CLAIM = "opentine_scope"
SUFFIX = "@scoped"
#: What each access grants at most; the operator's role policy may grant less.
READ_ACTIONS = frozenset({"capabilities", "read_ref", "fetch", "negotiate", "search"})
WRITE_ACTIONS = READ_ACTIONS | {"upload", "update_ref", "share"}
ACCESS = ("read", "write")
#: Most namespaces one token may carry.
MAX_NAMESPACES = 32


def _scope(identity: Any) -> dict[str, Any] | None:
    claims = getattr(identity, "claims", None) or {}
    if SCOPE_CLAIM not in claims:
        return None
    scope = claims[SCOPE_CLAIM]
    return scope if isinstance(scope, dict) else {}


def namespaces(identity: Any) -> tuple[str, ...] | None:
    """The namespaces a limited identity may reach; ``None`` when it is not limited."""
    scope = _scope(identity)
    if scope is None:
        return None
    refs = scope.get("refs")
    if not isinstance(refs, list) or not all(isinstance(item, str) and item for item in refs):
        return ()  # fail closed
    return None if "*" in refs else tuple(refs)


def access(identity: Any) -> str:
    scope = _scope(identity)
    if scope is None:
        return "write"
    return "write" if scope.get("access") == "write" else "read"


def in_namespace(prefixes: tuple[str, ...], name: str) -> bool:
    return any(name == p or (p.endswith("/") and name.startswith(p)) for p in prefixes)


def scoped_action(identity: Any, action: str) -> str:
    return action + SUFFIX if namespaces(identity) is not None else action


def visible_refs(identity: Any, refs: dict[str, str]) -> dict[str, str]:
    limited = namespaces(identity)
    if limited is None:
        return refs
    return {name: oid for name, oid in refs.items() if in_namespace(limited, name)}


def check_ref(identity: Any, name: str) -> None:
    limited = namespaces(identity)
    if limited is not None and not in_namespace(limited, name):
        raise AuthorizationDenied(f"ref {name} is outside the token's namespaces")


def check_wants(service: Any, identity: Any, tenant: str, wants: Any) -> None:
    """Refuse, as the uniform 404, a want that no visible ref targets."""
    if namespaces(identity) is None:
        return
    targets = set(visible_refs(identity, service.index.list_refs(tenant)).values())
    for want in wants if isinstance(wants, list) else [wants]:
        if want not in targets:
            raise KeyError("not found")


def check_namespaces(refs: Any) -> list[str]:
    """Validate the namespaces a token is minted with."""
    from opentine.repository._refs import normalize_ref

    if not isinstance(refs, list) or not 1 <= len(refs) <= MAX_NAMESPACES:
        raise ValueError(f"a token needs 1 to {MAX_NAMESPACES} ref namespaces")
    out: list[str] = []
    for item in refs:
        if item == "*":
            out.append(item)
            continue
        if not isinstance(item, str) or not item or "*" in item:
            raise ValueError("a ref namespace is '*', a ref, or a prefix ending in '/'")
        # A prefix is checked as the name of a ref inside it ("promotions/" -> "promotions/x").
        out.append(normalize_ref(item + "x")[:-1] if item.endswith("/") else normalize_ref(item))
    if "*" in out and len(out) > 1:
        raise ValueError("'*' already covers every ref; give it alone")
    return sorted(set(out))


class ScopedPolicy:
    """Wraps the operator's policy so a scoped token never exceeds its scope."""

    def __init__(self, inner: Any):
        self.inner = inner

    def authorize(self, identity: Any, action: str, tenant: str) -> bool:
        base = action.removesuffix(SUFFIX)
        if _scope(identity) is not None:
            allowed = WRITE_ACTIONS if access(identity) == "write" else READ_ACTIONS
            if base not in allowed:
                return False
            if namespaces(identity) is not None and action == base and base != "capabilities":
                return False  # a tenant-wide route: never for a namespace-limited token
        return bool(self.inner.authorize(identity, base, tenant))


__all__ = [
    "ACCESS",
    "SCOPE_CLAIM",
    "ScopedPolicy",
    "access",
    "check_namespaces",
    "check_ref",
    "check_wants",
    "in_namespace",
    "namespaces",
    "scoped_action",
    "visible_refs",
]
