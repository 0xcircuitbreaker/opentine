"""The billing an imported model call carries: never a free verdict or a cost from the source.

``tine price`` books a call ``unmetered`` ($0) only on positive evidence: the
capture's own ``unmetered`` verdict, or no billing inside a run the harness
wrapper captured. An imported trace is neither: its provider name, any billing
block and any cost figure are text from an untrusted file. Left without billing,
an imported step labelled ``ollama`` re-priced as a free local call (final
security pass 2, #2); carrying the source's own ``unmetered`` status, it did the
same; a block with an empty or missing status slipped past a check on the exact
word (final security pass 3, #2/#3); and the source's own ``cost`` was kept on
the step, so ``tine show``/``tine cost``/MCP reported whatever the file claimed
(final security pass 5, #6).

So the rule is an allowlist, not a denylist: before an import is recorded,
every source billing block is dropped, whatever it says, and every source cost
is moved out of the step's ``cost`` into the ``opentine.source_reported_cost``
attribute (kept for display and audit, never summed). ``Recorder.import_events``
applies this to every caller by default -- the documented library path as well
as ``tine import``. ``tine import --price`` then prices model calls from the
catalog, and any model call still without billing gets an explicit ``unknown``
record. The catalog can price it later; nothing in the source file can make it
free, or set its cost.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from typing import Any

from opentine._pricing_record import billable, read_record, recorded_status

#: The kinds :mod:`opentine._pricing_pass` prices (kept in step by a test).
_PRICEABLE = frozenset({"model"})
IMPORTED_NOTE = "imported trace: a provider name in a source file is a label, not a capture"
#: Where a source file's own cost figure is kept once it is no longer the step's cost.
SOURCE_COST = "opentine.source_reported_cost"


def without_source_cost(event: Any) -> Any:
    """*event* with its cost moved into :data:`SOURCE_COST` (display only)."""
    cost = getattr(event, "cost", None)
    if cost is None:
        return event
    if cost in ("", 0) or isinstance(cost, bool):
        return replace(event, cost=None)
    attributes = dict(getattr(event, "attributes", None) or {})
    attributes.setdefault(SOURCE_COST, str(cost)[:64])
    return replace(event, cost=None, attributes=attributes)


def distrust_source_billing(events: Sequence[Any]) -> list[Any]:
    """Drop every billing block and every cost a source file carried, on every event."""
    kept: list[Any] = []
    for event in events:
        if getattr(event, "billing", None):
            event = replace(event, billing={})
        kept.append(without_source_cost(event))
    return kept


def mark_unpriced(events: Sequence[Any]) -> list[Any]:
    """Give every model call without a readable billing status an ``unknown`` record."""
    marked: list[Any] = []
    for event in events:
        kind = read_record(event)[0]
        if billable(kind, event, _PRICEABLE) and recorded_status(event) is None:
            event = replace(event, billing={"status": "unknown", "warnings": [IMPORTED_NOTE]})
        marked.append(event)
    return marked


__all__ = [
    "IMPORTED_NOTE",
    "SOURCE_COST",
    "distrust_source_billing",
    "mark_unpriced",
    "without_source_cost",
]
