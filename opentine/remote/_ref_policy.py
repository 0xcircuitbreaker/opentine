"""Which ref moves need more than the ``update_ref`` permission.

Any writer could move ``promotions/*`` -- the refs a release pipeline deploys
from -- and re-point an existing ``tags/*`` ref at another run. By default both
now need the ``admin`` role: a promotion is an ``update_ref`` that also needs
``promote``, and moving or replacing a tag one that also needs ``retag``.
Creating a new tag stays a writer's (a CAS from "absent"). An operator relaxes
it with ``RoleAuthorizationPolicy(writer_promotes=True)`` (``tine serve
--writer-promotes``); a custom ``AuthorizationPolicy`` decides ``promote`` and
``retag`` itself.

``heads/*`` can also be made fast-forward-only (``RemoteService(
fast_forward_heads=True)``): a head may then move only to a run that descends
from the one it names -- a fork or resume of it (``forked_from``), or a run whose
events include every tip of it. Anything else is a rewrite, and needs
``force_update_ref`` (``admin``) plus an explicit ``force`` from the client; it is
audited as ``forced``. It is off by default because in opentine a head is usually
re-pointed at each new run, which does not continue the last one.
"""

from __future__ import annotations

from typing import Any

PROMOTE = "promote"
RETAG = "retag"
FORCE = "force_update_ref"
#: Runs a descent check may read before it gives up (and refuses).
MAX_DESCENT_STEPS = 2048


def ref_permission(name: str, expected_old: str | None) -> str | None:
    """The extra action moving *name* from *expected_old* needs, if any."""
    if name.startswith("promotions/"):
        return PROMOTE
    if name.startswith("tags/") and expected_old is not None:
        return RETAG
    return None


def descends(repo: Any, old: str, new: str, *, budget: int = MAX_DESCENT_STEPS) -> bool:
    """Whether run *new* continues run *old*: forked/resumed from it, or holds its tips.

    Bounded: a lineage longer than *budget* runs counts as not descending, so the
    check fails closed instead of walking an attacker-sized chain.
    """
    if old == new:
        return True
    try:
        old_payload = repo.get(old).payload()
    except (KeyError, ValueError):
        return False
    old_tips = set(old_payload.get("tips") or old_payload.get("events") or [])
    current: str | None = new
    seen: set[str] = set()
    while current and current not in seen and len(seen) < budget:
        seen.add(current)
        if current == old:
            return True
        try:
            envelope = repo.get(current)
        except (KeyError, ValueError):
            return False
        if envelope.object_type != "run":
            return False
        payload = envelope.payload()
        if old_tips and old_tips <= set(payload.get("events") or []):
            return True
        parent = payload.get("forked_from")
        current = parent if isinstance(parent, str) else None
    return False


def fast_forward_violation(
    repo: Any, name: str, old: str | None, new: str, *, enabled: bool
) -> bool:
    """True when *name* may only fast-forward and *old* -> *new* is not one."""
    if not enabled or not name.startswith("heads/") or old is None:
        return False
    return not descends(repo, old, new)
