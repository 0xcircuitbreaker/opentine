"""Role-scoped ``tine serve`` tokens: ingest-only, verdict-only, approve-only (0.90).

A role narrows a scoped token (``_token_scope``) further than read or write. It
is carried in the token's ``opentine_scope`` claim as ``role`` (and ``agent``,
the id the token acts as), and :class:`~_token_scope.ScopedPolicy` grants a
role token exactly the actions of :data:`ROLE_ACTIONS` and nothing else:

- ``ingest`` uploads packs and moves refs inside its namespaces. It reads
  nothing, not even the ref list, so a leaked ingest token discloses no data.
- ``verdict`` is what an out-of-process monitor needs: read and fetch inside
  its namespaces (the runs it judges) and upload plus ref moves inside them
  (its verdict and heartbeat attestations).
- ``approve`` reads and records Review gate decisions. It moves no ref, uploads
  nothing and edits no Review. An approval is refused when any run the decided
  Review covers was authored by the token's own agent id (:func:`self_authored`).

Ingest and verdict tokens must name their namespaces (``*`` is refused): a
role token never moves a ref outside the namespaces it was minted for. Every
route asks for ``ACTION@scoped`` (role tokens are always treated as scoped),
so a tenant-wide route that is not listed below refuses them. An unknown role
in a claim fails closed: it grants nothing.

Authorship: every ref move and every installed run is noted against the agent
that made it (the token's ``agent``, else the identity's subject) through
``service.authorship`` (the token store's ``note_authors``). A run whose
payload names an ``agent_id``, ``agent`` or ``author`` is attributed to that
id too. An approve token's own ids are its ``agent`` and its subject; a run the
tenant does not hold cannot be attributed, so an approval over it is refused
(fail closed).
"""

from __future__ import annotations

from typing import Any

ROLES = ("ingest", "verdict", "approve")
APPROVE = "approve"
_S = "@scoped"
ROLE_ACTIONS: dict[str, frozenset[str]] = {
    "ingest": frozenset({"capabilities", "upload" + _S, "update_ref" + _S}),
    "verdict": frozenset(
        {"capabilities", "read_ref" + _S, "fetch" + _S, "negotiate" + _S}
        | {"upload" + _S, "update_ref" + _S}
    ),
    "approve": frozenset(
        {"capabilities", "read_ref", "read_ref" + _S, "fetch", "fetch" + _S}
        | {"negotiate", "negotiate" + _S, APPROVE + _S}
    ),
}
#: What an action of a role token is asked as of the operator's policy.
INNER = {APPROVE: "update_ref"}
#: Roles whose tokens must name their ref namespaces (no ``*``).
NEEDS_NAMESPACES = frozenset({"ingest", "verdict"})
AGENT_MAX = 128
_ID_FIELDS = ("agent_id", "agent", "author")


def _scope(identity: Any) -> dict[str, Any]:
    from opentine.remote._token_scope import SCOPE_CLAIM

    scope = (getattr(identity, "claims", None) or {}).get(SCOPE_CLAIM)
    return scope if isinstance(scope, dict) else {}


def role(identity: Any) -> str | None:
    """The role of a role token; ``""`` for a malformed one; ``None`` for none."""
    scope = _scope(identity)
    if "role" not in scope:
        return None
    value = scope["role"]
    return value if value in ROLES else ""


def agent(identity: Any) -> str:
    """The id this identity acts as: a token's ``agent``, else its subject."""
    value = _scope(identity).get("agent")
    return value if isinstance(value, str) and value else str(getattr(identity, "subject", ""))


def own_ids(identity: Any) -> set[str]:
    return {item for item in (agent(identity), str(getattr(identity, "subject", ""))) if item}


def allows(identity: Any, action: str) -> bool:
    """Whether a role token may ask for *action* at all (``ScopedPolicy``)."""
    return action in ROLE_ACTIONS.get(role(identity) or "", frozenset())


def decide_action(identity: Any) -> str:
    """The action the Review decision route asks for."""
    return APPROVE + _S if role(identity) is not None else "update_ref"


def check_mint(role_name: str | None, refs: list[str], agent_id: str) -> None:
    if role_name is None:
        if agent_id:
            raise ValueError("--agent is given with a --role")
        return
    if role_name not in ROLES:
        raise ValueError("role is " + ", ".join(ROLES))
    if role_name in NEEDS_NAMESPACES and "*" in refs:
        raise ValueError(f"an {role_name} token names its ref namespaces; '*' is refused")
    if role_name == APPROVE and not agent_id:
        raise ValueError("an approve token names the agent id it acts as")
    if not isinstance(agent_id, str) or len(agent_id) > AGENT_MAX or not agent_id.isprintable():
        raise ValueError(f"an agent id is at most {AGENT_MAX} printable characters")


def note_authors(service: Any, identity: Any, tenant: str, oids: list[str]) -> None:
    hook = getattr(service, "authorship", None)
    runs = [oid for oid in oids if isinstance(oid, str) and oid.startswith("run:")]
    if callable(hook) and runs:
        hook(tenant, runs, agent(identity))


def _payload_ids(service: Any, tenant: str, oid: str) -> set[str] | None:
    from opentine.kernel import ObjectEnvelope

    try:
        payload = ObjectEnvelope.decode(service.objects.get(tenant, oid), oid).payload
    except (KeyError, FileNotFoundError, ValueError):
        return None
    found: set[str] = set()
    for where in (payload, payload.get("metadata") if isinstance(payload, dict) else None):
        for name in _ID_FIELDS if isinstance(where, dict) else ():
            value = where.get(name)
            value = value.get("id") if isinstance(value, dict) else value
            if isinstance(value, str) and value:
                found.add(value)
    return found


def self_authored(service: Any, identity: Any, tenant: str, version: dict) -> str | None:
    """Why an approve token may not approve *version*; ``None`` when it may."""
    from opentine._review_rules import review_body

    mine = own_ids(identity)
    lookup = getattr(service, "authors_of", None)
    for row in review_body(version)["subjects"]:
        if row.get("type") != "run":
            continue
        ids = _payload_ids(service, tenant, row["id"])
        if ids is None:
            return f"run {row['id']} is not held here: its author cannot be checked"
        if callable(lookup):
            ids |= lookup(tenant, row["id"])
        if ids & mine:
            return f"run {row['id']} was authored by this token's own agent id"
    return None


__all__ = [
    "APPROVE",
    "INNER",
    "ROLES",
    "ROLE_ACTIONS",
    "agent",
    "allows",
    "check_mint",
    "decide_action",
    "note_authors",
    "own_ids",
    "role",
    "self_authored",
]
