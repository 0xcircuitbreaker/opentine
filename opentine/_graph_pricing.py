"""Pricing-manifest slicing for forks, split out of _graph_analysis.

``validate_run_record`` deliberately does not constrain ``manifest.pricing``,
so every value read here may be an arbitrary JSON shape from a hand-edited or
third-party artifact. The billing writer (``_pin_billing``) only ever emits
``str`` step references, ``str | None`` catalog references, and ``str``
statuses; anything else can never match a retained step or a catalog
snapshot. Each membership probe below therefore treats non-conforming values
as not-matching instead of letting ``set``/``dict`` hashing raise TypeError —
the data itself is preserved untouched wherever it is not being filtered.
"""

from __future__ import annotations


def _catalog_key(item: dict) -> tuple[str | None, str | None] | None:
    """The (catalog_id, catalog_hash) pair, or None if the shape is malformed."""
    catalog_id, catalog_hash = item.get("catalog_id"), item.get("catalog_hash")
    if all(value is None or isinstance(value, str) for value in (catalog_id, catalog_hash)):
        return (catalog_id, catalog_hash)
    return None


def _slice_pricing(manifest: dict, retained: set[str]) -> None:
    pricing = manifest.get("pricing")
    if not isinstance(pricing, dict) or "invocations" not in pricing:
        return
    invocations = [
        item
        for item in pricing.get("invocations") or []
        # Retained IDs are always strings, so a non-str step_id never matches.
        if isinstance(item, dict)
        and isinstance(item.get("step_id"), str)
        and item["step_id"] in retained
    ]
    pricing["invocations"] = invocations
    cards = pricing.get("rate_cards")
    if isinstance(cards, dict):
        pricing["rate_cards"] = {key: value for key, value in cards.items() if key in retained}
    referenced = {key for item in invocations if (key := _catalog_key(item)) is not None}
    catalogs = pricing.get("catalogs")
    if isinstance(catalogs, list):
        catalogs = [
            item for item in catalogs if isinstance(item, dict) and _catalog_key(item) in referenced
        ]
        pricing["catalogs"] = catalogs
    else:
        # Loading tolerates a malformed catalogs shape; fork finds no snapshot in it.
        catalogs = []
    pricing["complete"] = all(
        # Tuple membership compares by equality, so a malformed status is
        # simply not complete rather than a hashing TypeError.
        item.get("status") in ("complete", "unmetered")
        for item in invocations
    )
    first = invocations[0] if invocations else {}
    catalog_id, catalog_hash = first.get("catalog_id"), first.get("catalog_hash")
    for name, value in (("catalog_id", catalog_id), ("catalog_hash", catalog_hash)):
        if value:
            pricing[name] = value
        else:
            pricing.pop(name, None)
    snapshot = next(
        (
            item
            for item in catalogs or []
            if item.get("catalog_id") == catalog_id and item.get("catalog_hash") == catalog_hash
        ),
        None,
    )
    provenance = (snapshot or {}).get("catalog_provenance")
    if provenance:
        pricing["catalog_provenance"] = provenance
    else:
        pricing.pop("catalog_provenance", None)
