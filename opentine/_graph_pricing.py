"""Pricing-manifest slicing for forks, split out of _graph_analysis.

``validate_run_record`` deliberately does not constrain ``manifest.pricing``,
so every value read here may be an arbitrary JSON shape from a hand-edited or
third-party artifact. The billing writer (``_pin_billing``) only ever emits
``str`` step references, ``str | None`` catalog references, and ``str``
statuses; anything else can never match a retained step or a catalog
snapshot. Each membership probe below therefore treats non-conforming values
as not-matching instead of letting ``set``/``dict`` hashing raise TypeError —
the data itself is preserved untouched wherever it is not being filtered.

The same rule applies one level up: every *container* read here
(``pricing`` itself, ``invocations``, ``rate_cards``, ``catalogs``) is shape
checked before it is iterated or indexed, because ``x or []`` rescues only
falsey values and a truthy scalar in a container position raises
``TypeError: … is not iterable`` before any item guard runs.
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
    if not isinstance(pricing, dict):
        return
    cards = pricing.get("rate_cards")
    if isinstance(cards, dict):
        # Dict keys are hashable by construction, so membership cannot raise.
        # This runs whatever ``invocations`` turns out to be, including absent:
        # the cards are keyed by step id, so a dropped step's card left behind
        # hands the child a reference to a step it does not contain, which the
        # repository then refuses to store as an unknown step reference.
        pricing["rate_cards"] = {key: value for key, value in cards.items() if key in retained}
    raw = pricing.get("invocations")
    if not isinstance(raw, list):
        # A missing or non-list container cannot be filtered, so it is preserved
        # exactly as loaded and nothing is derived from it. ``or []`` alone
        # would rescue only falsey shapes — a truthy scalar raised TypeError —
        # and deriving ``complete`` from a container this function cannot read
        # would launder a ``complete: false`` manifest into ``complete: true``
        # across a fork, silencing the strict_cost refusal on the child run.
        return
    invocations = [
        item
        for item in raw
        # Retained IDs are always strings, so a non-str step_id never matches.
        if isinstance(item, dict)
        and isinstance(item.get("step_id"), str)
        and item["step_id"] in retained
    ]
    pricing["invocations"] = invocations
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
