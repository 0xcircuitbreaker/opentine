"""Read back the accounting an OpenTine export writes onto an OTLP span.

The reader half of the two ``opentine.*`` keys :mod:`opentine.trace.exporters`
writes for money — cost and billing, neither of which the GenAI conventions
spell. For one release there was no reader half at all: export wrote both keys
and :func:`opentine.trace.otel_genai_events` walked past them, so a natively
priced run exported to OTel and imported back came home with ``cost=None``,
billing dropped, and ``$0.00`` printed against it. That is the same writer/reader
asymmetry every silent data-loss bug in this project has been.

Two rules keep the reader safe on foreign spans, which may spell these keys
anything at all:

* a value :class:`~opentine.trace.schema.TraceEvent` would refuse — a word where
  a decimal belongs, a negative amount, a billing scalar — is *left in the
  attributes* rather than coerced or dropped, so the span still imports and its
  raw value stays visible to whoever reads the event;
* an accepted amount travels in the exact decimal spelling the span carried,
  never through a float, so money neither drifts on the hop nor re-exports as
  different bytes than it arrived as.
"""

from __future__ import annotations

import math
from decimal import Decimal, InvalidOperation
from typing import Any

from opentine.trace import _genai_semconv as semconv

#: The billing key holding a priced subtotal, which ``TraceEvent`` meters exactly
#: as it meters ``cost``; the rest of a billing mapping is free-form.
SUBTOTAL = "known_subtotal_usd"


def otel_accounting(attributes: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    """Take the ``(cost, billing)`` a span carries out of its attributes.

    Consumed, not copied — as with the kind attribute. The exporter writes both
    keys back from the fields they are read into here, so a value left behind
    would be written twice and an imported span would stop re-exporting to the
    bytes it came from.
    """
    cost = attributes.get(semconv.COST_ATTRIBUTE)
    billing = attributes.get(semconv.BILLING_ATTRIBUTE)
    if isinstance(billing, dict) and _metered(billing.get(SUBTOTAL, 0)):
        del attributes[semconv.BILLING_ATTRIBUTE]
    else:
        billing = {}
    if _metered(cost):
        del attributes[semconv.COST_ATTRIBUTE]
    else:
        cost = None
    return cost, billing


def _metered(value: Any) -> bool:
    """Whether the event store would accept *value* as an amount.

    Deliberately the same judgement ``repository._run_graph._meter`` makes on the
    stored form, float-compatibility check included: an amount that passes here
    constructs a ``TraceEvent`` and appends, instead of raising a ``ValueError``
    out of the constructor — or a ``KernelError`` out of ``repo.put`` — and
    failing an import over one foreign attribute.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return False
    if isinstance(value, str) and len(value) > 128:
        return False
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return False
    return number.is_finite() and number >= 0 and math.isfinite(float(number))
