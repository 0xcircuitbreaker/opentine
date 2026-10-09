"""Which catalog layers ``load_catalogs`` lets decide a price.

* **The workspace overlay is opt-in.** ``./.tine/pricing.json`` is read from
  whatever directory the process runs in -- the directory ``tine init`` creates,
  so a cloned project can ship one -- and it outranks the user's own overlay
  and the bundled catalog. Unsigned, it re-priced any model to $0, which also
  disarmed every ``max_cost`` budget computed from the catalog. It now applies
  only when validly signed by a trusted key, or when the operator sets
  ``OPENTINE_TRUST_WORKSPACE_PRICING=1``.
* **A signed catalog never rolls prices back.** ``install_catalog`` accepted any
  validly signed catalog, and the user slot outranks the bundled one, so an
  older signed catalog -- installed by mistake, or replayed by whoever could
  write the file -- masked newer bundled cards, even across upgrades. A signed
  catalog is compared by ``generated_at``: one older than the bundled snapshot
  (or than the one it would replace) is refused at install and skipped at load.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

TRUST_WORKSPACE_PRICING_ENV = "OPENTINE_TRUST_WORKSPACE_PRICING"
_TRUE = frozenset({"1", "true", "yes", "on"})


def workspace_pricing_trusted() -> bool:
    """Whether the operator opted in to an unsigned workspace overlay."""
    return os.environ.get(TRUST_WORKSPACE_PRICING_ENV, "").strip().lower() in _TRUE


def generated_at(data: Any) -> datetime | None:
    """A catalog's ``generated_at`` as an aware datetime, or ``None`` if absent/invalid."""
    value = data.get("generated_at") if isinstance(data, dict) else None
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def older(candidate: datetime | None, reference: datetime | None) -> bool:
    """Whether *candidate* is a rollback against *reference*.

    No reference means nothing to roll back from; an undated candidate cannot
    show it is not one, so it counts as older.
    """
    if reference is None:
        return False
    return candidate is None or candidate < reference


__all__ = [
    "TRUST_WORKSPACE_PRICING_ENV",
    "generated_at",
    "older",
    "workspace_pricing_trusted",
]
