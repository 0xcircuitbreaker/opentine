"""The money half of the OTel round trip: cost and billing, out and back.

Gap B of the 0.7.1 health audit, and the fourth instance of this project's one
recurring bug shape -- a writer that spells a field and a reader that does not.
``opentine.trace.exporters`` has always written a step's cost to
``opentine.cost_usd`` and its billing to ``opentine.billing`` (the GenAI
conventions define neither), while ``otel_genai_events`` built its ``TraceEvent``
with no ``cost=`` and no ``billing=``; ``_record_event.put_trace_event`` then
wrote ``cost: 0`` into the store for want of one. So a natively priced run that
went out to OpenTelemetry and came back reported **$0.00** with its rate card
gone -- exit 0, no warning, and nothing in the document to say the money had
been read at all. It was all still there, on the two attributes nobody read.

The tests below are the two halves of that claim: an exported priced run comes
back priced (in an event, and in a repository once the import command's Recorder
has written it), and a *foreign* span that spells these keys its own way -- a
word instead of a decimal, a negative amount, a scalar where a billing mapping
belongs -- still imports, with the unusable value left visible in the attributes
rather than coerced into the accounting or dropped on the floor.
"""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from opentine import Repo, Run, StepKind
from opentine._cli_json import serialize
from opentine.trace import otel_genai_events, to_otel_genai, to_otel_genai_document
from opentine.trace.exporters import BILLING_ATTRIBUTE, COST_ATTRIBUTE
from opentine.trace.importers import native_events
from opentine.trace.recorder import Recorder

BILLING = {"known_subtotal_usd": "0.0125", "rate_card": "r3", "status": "known"}


@pytest.fixture
def priced() -> Run:
    """One step that cost real money, priced natively the way a provider prices."""
    run = Run(id="priced-source")
    run.add_step(
        StepKind.model,
        {"prompt": "what does it cost"},
        {"text": "0.0125"},
        usage={"input": 11, "output": 7},
        billing=dict(BILLING),
        cost=0.0125,
        model_info="anthropic:claude-opus-5",
    )
    run.add_step(StepKind.tool, {"tool": "grep"}, {"hits": 0}, tool_info={"name": "grep"})
    return run


def _document(run: Run) -> dict:
    """The run as a document that has been through bytes, like a real export."""
    return json.loads(serialize(to_otel_genai_document(run)))


def test_an_exported_priced_run_imports_back_priced(priced):
    events = otel_genai_events(_document(priced))

    step, event = priced.steps[0], events[0]
    assert Decimal(str(event.cost)) == Decimal(str(step.cost)) == Decimal("0.0125"), (
        "the cost the exporter wrote to opentine.cost_usd must come back on the field"
    )
    assert event.billing == BILLING, "the whole billing mapping, rate card included"
    # Consumed, not duplicated: the exporter writes both keys back from these
    # fields, so a copy left in the attributes would be written twice.
    assert COST_ATTRIBUTE not in event.attributes
    assert BILLING_ATTRIBUTE not in event.attributes
    free = events[1]
    # A step the run recorded at zero comes back at zero, billing empty: the
    # exporter writes the amount it holds, so import is not inventing this.
    assert Decimal(str(free.cost)) == 0 and free.billing == {}


def test_the_amount_crosses_in_the_decimal_spelling_it_was_written_in(priced):
    """Every digit of the amount, not a re-parsed approximation of it.

    An accounting field that comes back *nearly* right is worse than one that
    comes back missing, because nothing flags it -- so the reader carries the
    span's decimal string through verbatim instead of routing money through
    another float conversion on the way in.
    """
    run = Run(id="exact")
    run.add_step(StepKind.model, {}, {}, cost=0.1 + 0.2)

    event = otel_genai_events(_document(run))[0]
    assert event.cost == "0.30000000000000004"
    assert Decimal(str(event.cost)) == Decimal(repr(0.1 + 0.2))


def test_a_reimported_priced_run_is_still_priced_in_the_store(priced, tmp_path):
    """The durable half: what ``tine import`` writes into a repository.

    ``put_trace_event`` defaults a missing cost to ``0``, so an unpriced event
    does not merely display as $0.00 -- it is *stored* as zero, and every later
    read of that run (``tine show``, ``tine stats``, a cost budget) agrees with
    the zero rather than with what the run actually cost.
    """
    recorder = Recorder.start(Repo.init(tmp_path / "repo"), ref="heads/main", capture=False)
    recorder.import_events(otel_genai_events(_document(priced)))
    rebuilt = recorder.repo.load_run(recorder.finalize())

    charged = [step for step in rebuilt.steps if Decimal(str(step.cost or 0))]
    assert len(charged) == 1, "the priced step is priced, and nothing else became priced"
    assert Decimal(str(charged[0].cost)) == Decimal("0.0125")
    assert charged[0].billing == BILLING


def test_the_round_trip_is_still_a_fixed_point_now_that_the_money_is_read(priced):
    """Reading the two keys must not change what a re-export writes.

    The importer *consumes* them, exactly as it consumes the kind attribute, and
    the exporter writes them back from the fields at the same position -- so a
    document exported, imported and exported again is byte-identical, which is
    what lets a collector re-emit an OpenTine document without drifting.
    """
    events = otel_genai_events(_document(priced))
    assert to_otel_genai(events) == to_otel_genai(native_events(priced))
    assert otel_genai_events(to_otel_genai_document(events)) == events


def _span(**attributes) -> dict:
    return {
        "traceId": "foreign-trace",
        "spanId": "foreign-span",
        "name": "chat",
        "attributes": [{"key": key, "value": value} for key, value in attributes.items()],
    }


def test_a_foreign_span_without_the_opentine_keys_imports_unpriced(priced):
    event = otel_genai_events([_span(**{"gen_ai.operation.name": {"stringValue": "chat"}})])[0]
    assert event.cost is None and event.billing == {}
    assert event.actor == "chat", "the rest of the span imported normally"


@pytest.mark.parametrize(
    "value",
    [
        {"stringValue": "free"},  # a word where a decimal belongs
        {"doubleValue": -3.0},  # a refund is not a cost the store accepts
        {"stringValue": "nan"},  # parses as Decimal, is not finite
        {"stringValue": "1e999999999"},  # finite Decimal, infinite float
        {"boolValue": True},  # a flag, not an amount
        {"arrayValue": {"values": [{"doubleValue": 1.0}]}},  # not a scalar at all
    ],
)
def test_an_unusable_cost_is_left_in_the_attributes_not_forced_into_the_field(value):
    """A foreign span must import, and its odd value must stay visible.

    Two failure modes are refused at once: crashing the import over one
    attribute (``TraceEvent`` rejects a negative or non-finite cost, and the
    event store rejects it again), and quietly deleting the value while reading
    it. Whoever reads the event sees exactly what the span said.
    """
    event = otel_genai_events([_span(**{COST_ATTRIBUTE: value})])[0]
    assert event.cost is None, "an amount the store would refuse never becomes the cost"
    assert COST_ATTRIBUTE in event.attributes, "and it is not dropped either"


def test_an_unusable_billing_mapping_is_left_in_the_attributes(priced):
    scalar = otel_genai_events([_span(**{BILLING_ATTRIBUTE: {"stringValue": "none"}})])[0]
    assert scalar.billing == {} and scalar.attributes[BILLING_ATTRIBUTE] == "none"

    bad_subtotal = {
        "kvlistValue": {
            "values": [{"key": "known_subtotal_usd", "value": {"stringValue": "priceless"}}]
        }
    }
    refused = otel_genai_events([_span(**{BILLING_ATTRIBUTE: bad_subtotal})])[0]
    assert refused.billing == {}, "a subtotal TraceEvent would refuse keeps the mapping out"
    assert refused.attributes[BILLING_ATTRIBUTE] == {"known_subtotal_usd": "priceless"}


def test_a_billing_mapping_without_a_subtotal_still_arrives(priced):
    """Only the metered key is judged; the rest of a billing mapping is free-form."""
    card = {"kvlistValue": {"values": [{"key": "rate_card", "value": {"stringValue": "r3"}}]}}
    event = otel_genai_events([_span(**{BILLING_ATTRIBUTE: card})])[0]
    assert event.billing == {"rate_card": "r3"} and BILLING_ATTRIBUTE not in event.attributes
