"""Write-time bounds that keep every pushed run fetchable and every ref listable.

Two control-plane reads used to enforce limits that no write checked:

* **Fetch.** ``reachable`` includes every annotation and attestation targeting a
  run, and refuses once a run's associations exceed the pack object limit. Any
  writer could upload ten thousand attestations naming someone else's run --
  touching no ref -- and that run could never be fetched, negotiated or cloned
  again. A pack is now refused at install if it would give any target more than
  :data:`MAX_ASSOCIATIONS_PER_TARGET` associated objects.
* **Listing.** ``GET /refs`` bound each ``annotations/<digest>`` ref to its run by
  decoding the annotation under a 1 MiB / 8 MiB budget, so one large annotation
  (an ordinary run with a big system prompt) made the listing -- and with it
  every fetch, clone and push in the tenant -- fail for good. The listing now
  reads the binding from the ``target_id`` recorded when the object was
  installed and verified, and decodes (under the old budget) only an object the
  index has no binding for; ``update_ref`` runs that same listing check with the
  new ref in place, so a write can no longer leave a listing that fails.
"""

from __future__ import annotations

import threading
from collections import Counter
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from typing import Any

from opentine.kernel import ObjectEnvelope

#: A run's annotation versions plus its attestations and evaluations. A thousand
#: is far beyond real use (each metadata edit or sign-off adds one) yet a tenth
#: of the pack object limit, so no run's associations alone can exhaust a fetch;
#: it is also the control plane's other per-tenant result bound.
MAX_ASSOCIATIONS_PER_TARGET = 1000

_ASSOCIATION_TYPES = frozenset({"annotation", "attestation"})
_ASSOCIATION_INSTALLS = threading.Lock()


def association_targets(order: list[tuple[str, bytes]]) -> dict[str, str | None]:
    """Each packed object's ``target_id`` if it is an annotation or attestation."""
    targets: dict[str, str | None] = {}
    for oid, raw in order:
        envelope = ObjectEnvelope.decode(raw, oid)
        payload = envelope.payload() if envelope.object_type in _ASSOCIATION_TYPES else None
        target = payload.get("target_id") if isinstance(payload, dict) else None
        targets[oid] = target if isinstance(target, str) else None
    return targets


def recorded_targets(index: Any, tenant: str, oids) -> dict[str, str]:
    """The index's install-time bindings, or none for an index that keeps none."""
    lookup = getattr(index, "recorded_targets", None)
    return dict(lookup(tenant, list(oids))) if callable(lookup) else {}


def _refuse(target: str) -> None:
    raise ValueError(
        f"upload would give {target} more than {MAX_ASSOCIATIONS_PER_TARGET} "
        "associated annotations and attestations"
    )


def check_association_budget(tenant: str, index: Any, targets: dict[str, str | None]) -> None:
    """Refuse a pack that would push any target past its association budget."""
    incoming = {oid: target for oid, target in targets.items() if target is not None}
    if not incoming:
        return
    counts = getattr(index, "association_counts", None)
    if callable(counts):
        known = recorded_targets(index, tenant, incoming)
        added = Counter(target for oid, target in incoming.items() if oid not in known)
        existing = counts(tenant, list(added))
        for target, count in sorted(added.items()):
            if existing.get(target, 0) + count > MAX_ASSOCIATIONS_PER_TARGET:
                _refuse(target)
        return
    # An index without counts: its bounded association lookup, as fetch uses it.
    for target in sorted(set(incoming.values())):
        new = {oid for oid, item in incoming.items() if item == target}
        try:
            stored = set(index.associated_objects(tenant, target, MAX_ASSOCIATIONS_PER_TARGET))
        except ValueError:
            _refuse(target)
        if len(stored | new) > MAX_ASSOCIATIONS_PER_TARGET:
            _refuse(target)


def association_guard(targets: dict[str, str | None]) -> AbstractContextManager:
    """Serialize installs that add associations, from budget check to last record.

    Two installs (the server runs two at once) could each pass the check against
    the same count and together overshoot a target's budget by a pack. Installs
    without associations -- most of a push -- never wait. The lock is per
    process: one server process per store, as the reference server runs.
    """
    if any(target is not None for target in targets.values()):
        return _ASSOCIATION_INSTALLS
    return nullcontext()


@contextmanager
def admitted_associations(
    tenant: str, index: Any, order: list[tuple[str, bytes]]
) -> Iterator[dict[str, str | None]]:
    """Check *order* against the budget and hold the guard while it is installed."""
    targets = association_targets(order)
    with association_guard(targets):
        check_association_budget(tenant, index, targets)
        yield targets
