"""Which ref moves need more than the ``update_ref`` permission.

Any writer could move ``promotions/*`` -- the refs a release pipeline deploys
from -- and re-point an existing ``tags/*`` ref at another run. By default both
now need the ``admin`` role: a promotion is an ``update_ref`` that also needs
``promote``, and moving or replacing a tag one that also needs ``retag``.
Creating a new tag stays a writer's (a CAS from "absent"). An operator relaxes
it with ``RoleAuthorizationPolicy(writer_promotes=True)`` (``tine serve
--writer-promotes``); a custom ``AuthorizationPolicy`` decides ``promote`` and
``retag`` itself.
"""

from __future__ import annotations

PROMOTE = "promote"
RETAG = "retag"


def ref_permission(name: str, expected_old: str | None) -> str | None:
    """The extra action moving *name* from *expected_old* needs, if any."""
    if name.startswith("promotions/"):
        return PROMOTE
    if name.startswith("tags/") and expected_old is not None:
        return RETAG
    return None
