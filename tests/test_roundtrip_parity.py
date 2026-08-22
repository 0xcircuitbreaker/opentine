"""The permanent parity gate for writer/reader (and writer/writer) asymmetry.

Every serious data-loss bug this project has shipped has had one shape: two code
paths that are supposed to spell the same run, and one of them quietly spells
less.  A field the repository writer stores and the ``.tine`` writer has no slot
for; a reader that pops an attribute and then only puts back the half that
happened to be empty; an exporter that reuses the *lenient* import coercion and
replaces content with a marker.  Each exits 0, and the loss is visible only by
comparing what went in against what came back out -- which is what this module
does, permanently, on one representative run, through all three carriers.

(a) repository -> ``.tine`` -> ``Run.load``; (b) ``.tine`` -> a *fresh*
repository -> ``load_run``; (c) run -> OTel GenAI document -> importer.

The run is built to hit every asymmetry a carrier could have: all five
``StepKind`` values, a diamond whose causal ancestor is unreachable through
parents, a fork whose retained slice depends on that causal edge, tags,
metadata, usage, a priced cost with its billing, and deeply nested inputs and
outputs.  Each test names the asymmetry it guards; a fix reverted upstream fails
here, not in an archive.
"""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from opentine import Repo, Run, StepKind
from opentine._cli_json import serialize
from opentine._graph_analysis import retained_closure
from opentine.trace import _genai_semconv as semconv
from opentine.trace import otel_genai_events, to_otel_genai, to_otel_genai_document
from opentine.trace.recorder import Recorder

#: Positions in the representative run, which every carrier must preserve in
#: order.  ``DIAMOND_TIP`` is the step whose ``causal_ids`` name ``CAUSAL_EDGE``,
#: a step no chain of ``parent_ids`` reaches from it.
CAUSAL_EDGE = 1
DIAMOND_TIP = 3


def nest(levels: int, leaf: object = "deep-leaf") -> object:
    value: object = leaf  # a chain a truncating coercion replaces with a marker
    for _ in range(levels):
        value = {"n": value}
    return value


def _representative_run() -> Run:
    """One run exercising every field and edge a carrier could silently drop.

    ``a`` roots the graph; ``b`` (tool) and ``c`` (think) branch off it; ``d``
    descends from ``c`` alone but *causally* required ``b``; ``e`` closes the
    run and ``f`` records a failure under ``b``.  A fork from ``d`` therefore
    keeps ``b`` only while the causal edge survives the trip.
    """
    run = Run(id="parity-source")
    run.model_info = "anthropic:claude-opus-5"
    run.metadata["project"] = "parity-gate"
    run.add_tag("Release")  # normalized to "release": the tag carrier must agree
    a = run.add_step(
        StepKind.model,
        {
            "messages": [
                {"role": "system", "content": "be careful"},
                {"role": "user", "content": [{"type": "text", "text": "plan it"}]},
            ]
        },
        {"text": "planning"},
        usage={"input": 120, "output": 45, "cache_read": 10},
        billing={"known_subtotal_usd": "0.0042", "rate_card": "r3"},
        cost=0.0042,
        duration=1.5,
    )
    b = run.add_step(
        StepKind.tool,
        {"tool": "grep", "args": {"pattern": "x", "flags": ["-r", "-n"]}},
        {"matches": [{"file": "a.py", "line": 3}]},
        parent_ids=[a.id],
        tool_info={"name": "grep"},
    )
    c = run.add_step(StepKind.think, {"note": "branch"}, {"choice": "deep"}, parent_ids=[a.id])
    d = run.add_step(
        StepKind.model,
        {"prompt": "synthesize", "trace": nest(30)},
        {"text": "done", "evidence": nest(12)},
        parent_ids=[c.id],
        usage={"input": 9, "output": 3},
        billing={"known_subtotal_usd": "0.001"},
    )
    run.add_step(StepKind.done, {"summary": "finished"}, {"ok": True}, parent_ids=[d.id])
    run.add_step(
        StepKind.error,
        {"op": "cleanup"},
        {},
        parent_ids=[b.id],
        error={"type": "IOError", "message": "disk"},
    )
    # The carrier a repository run holds its causal edges in, which is exactly
    # the map ``load_run`` restores and ``put_run`` reads.
    run._v3_causal_ids = {d.id: [b.id]}
    return run


def _shape(run) -> list[dict]:
    """Every step field, with step ids replaced by their position in the run.

    Positions, not ids: a run written into a *fresh* repository is re-addressed,
    so identity comparison would only ever pass for the ``.tine`` trip.  Edges
    still compare exactly, because a dropped edge changes the position list.
    """
    index = {step.id: position for position, step in enumerate(run.steps)}
    return [
        {
            "kind": step.kind.value,
            "parents": [index[parent] for parent in step.parent_ids],
            "causal": [index[edge] for edge in step.causal_ids],
            "inputs": step.inputs,
            "outputs": step.outputs,
            "usage": step.usage,
            "billing": step.billing,
            "model_info": step.model_info,
            "tool_info": step.tool_info,
            "error": step.error,
            "timestamp": step.timestamp,
            "cost": step.cost,
            "duration": step.duration,
        }
        for step in run.steps
    ]


def _money(run) -> list[tuple[str, str, str]]:
    """Every priced step as ``(payload, cost, billing)``, sorted.

    Keyed by content rather than by position or id: the OTel leg rebuilds the run
    in a *fresh* repository, which re-addresses every step and may order siblings
    differently, so only the payload identifies a step across that carrier.
    Amounts compare as ``Decimal`` because money crosses OTel as an exact decimal
    *string* -- the conventions have no cost attribute to type it -- and
    ``"0.0042" != 0.0042`` while the amount is the same.
    """
    return sorted(
        (
            json.dumps(step.inputs, sort_keys=True, default=str),
            str(Decimal(str(step.cost or 0))),
            json.dumps(step.billing, sort_keys=True, default=str),
        )
        for step in run.steps
        if Decimal(str(step.cost or 0)) or step.billing
    )


@pytest.fixture
def source(tmp_path) -> Run:
    """The representative run as a repository read it back: the writer side."""
    repo = Repo.init(tmp_path / "repo")
    return repo.load_run(repo.put_run(_representative_run(), ref="heads/main").run_id)


@pytest.fixture
def artifact(source, tmp_path):
    return source.save(tmp_path / "round.tine")


# --- (a) repository -> .tine -> Run.load -------------------------------------


def test_a_tine_round_trip_returns_every_step_field_unchanged(source, artifact):
    reloaded = Run.load(artifact)
    # Ids too, on this leg: ``.tine`` is content-addressed by the same ids the
    # repository minted, so anything short of identity is a loss.
    assert [step.id for step in reloaded.steps] == [step.id for step in source.steps]
    assert _shape(reloaded) == _shape(source)
    assert {step.kind for step in reloaded.steps} == set(StepKind)


def test_a_tine_round_trip_keeps_the_fork_slice_a_causal_edge_decides(source, artifact):
    """Guards finding #7: ``step_to_dict`` had no ``causal_ids`` slot.

    Reverted, the export drops every causal edge, so ``b`` leaves the closure and
    a fork of the reloaded run keeps a strictly smaller history than the same
    fork of the run it was exported from -- with a zero exit status.
    """
    tip = source.steps[DIAMOND_TIP]
    ancestor = source.steps[CAUSAL_EDGE]
    expected = retained_closure(source, tip.id)
    assert ancestor.id in expected and ancestor.id not in {
        step.id for step in source.ancestors(tip.id)
    }, "the causal ancestor is retained and is not reachable through parents"

    reloaded = Run.load(artifact)
    assert reloaded.get_step(tip.id).causal_ids == [ancestor.id]
    assert retained_closure(reloaded, tip.id) == expected
    assert set(reloaded.fork(tip.id).graph.steps) == set(source.fork(tip.id).graph.steps)


def test_a_tine_round_trip_keeps_tags_and_metadata(source, artifact):
    reloaded = Run.load(artifact)
    assert reloaded.tags == source.tags == ["release"]
    assert reloaded.metadata.get("project") == "parity-gate"
    assert reloaded.model_info == source.model_info


# --- (b) .tine -> a fresh repository -> load_run ------------------------------


def test_a_tine_artifact_rebuilds_into_a_fresh_repository_field_for_field(
    source, artifact, tmp_path
):
    """The other direction of the same asymmetry, and the writer/writer half:
    ``put_run`` builds its events from the ``Run`` in hand, so a field the
    ``.tine`` reader restored but the repository writer has no slot for is lost
    on the way back in -- invisibly, because the run still loads."""
    target = Repo.init(tmp_path / "target")
    rebuilt = target.load_run(target.put_run(Run.load(artifact), ref="heads/main").run_id)

    assert _shape(rebuilt) == _shape(source)
    assert rebuilt.tags == source.tags
    assert rebuilt.metadata.get("project") == "parity-gate"
    # The causal edge is re-attached as an edge, not flattened into a parent.
    tip = rebuilt.steps[DIAMOND_TIP]
    assert tip.causal_ids == [rebuilt.steps[CAUSAL_EDGE].id]
    assert tip.parent_ids == [rebuilt.steps[2].id]
    assert len(retained_closure(rebuilt, tip.id)) == len(
        retained_closure(source, source.steps[DIAMOND_TIP].id)
    )


# --- (c) run -> OTel GenAI document -> importer -------------------------------


def test_the_otel_round_trip_returns_every_input_and_output_verbatim(source):
    """Guards finding #5: the document writer reused the *lenient* coercion.

    Through ``serialize`` and back, because bytes are how a document travels and
    that is the writer that was wrong: its depth bound was the import policy's,
    and the OTLP envelope wraps every content level in four more, so ``nest(30)``
    was written as the string ``"[MAX_DEPTH]"`` where a subtree had been -- in a
    document that parsed, and re-imported with the content gone.
    """
    events = otel_genai_events(json.loads(serialize(to_otel_genai_document(source))))
    assert len(events) == len(source.steps)
    for step, event in zip(source.steps, events):
        assert event.inputs == step.inputs, step.kind
        assert event.outputs == step.outputs, step.kind
        assert event.span_id == step.id
    assert "[MAX_DEPTH]" not in str(events) and "[CIRCULAR]" not in str(events)


def test_the_otel_round_trip_returns_every_cost_and_billing_amount(source):
    """Guards Gap B: export wrote the money down and import walked straight past.

    ``opentine.cost_usd`` and ``opentine.billing`` are the two attributes export
    has always carried the money in -- the GenAI conventions name neither -- and
    the importer's ``TraceEvent`` had no ``cost=`` or ``billing=`` argument, so
    every span came back unpriced and ``_record_event`` then defaulted the cost
    to ``0``.  Reverted, a natively priced run exported to OTel reports $0.00
    with its rate card gone, at exit 0: metering, lost on one hop.
    """
    events = otel_genai_events(json.loads(serialize(to_otel_genai_document(source))))
    by_span = {event.span_id: event for event in events}
    for step in source.steps:
        event = by_span[step.id]
        assert Decimal(str(event.cost or 0)) == Decimal(str(step.cost or 0)), step.kind
        assert event.billing == step.billing, step.kind
    charged = [event for event in events if Decimal(str(event.cost or 0))]
    assert charged, "a parity gate run over an unpriced run would prove nothing"
    assert [event.billing.get("rate_card") for event in charged] == ["r3"]


def test_an_otel_document_rebuilds_a_priced_run_into_a_repository_still_priced(source, tmp_path):
    """The same money over the carrier a user runs: ``tine export | tine import``.

    The import half is where an unpriced event becomes a durable ``cost: 0`` --
    ``put_trace_event`` defaults it while writing the run -- so the loss is in
    the store the moment the document lands, not just in an in-memory event.
    Rebuilt through the same ``Recorder`` the import command drives.
    """
    events = otel_genai_events(json.loads(serialize(to_otel_genai_document(source))))
    recorder = Recorder.start(Repo.init(tmp_path / "priced"), ref="heads/main", capture=False)
    recorder.import_events(events)
    rebuilt = recorder.repo.load_run(recorder.finalize())

    assert _money(source), "the representative run is priced"
    assert _money(rebuilt) == _money(source)


def test_a_rewritten_classic_scalar_does_not_delete_the_structured_conversation(source):
    """Guards finding #6: two writers of one payload, one of them carrying more.

    Every exported span holds both content generations.  A collector, or any
    other SDK on the hop, may rewrite the 1.27 scalar to a summary while leaving
    the 1.36 messages whole -- the shape where the two writers disagree.  The
    importer prefers the scalar, and used to restore the modern attribute only
    when its side was still *empty*, so the whole conversation (system prompt
    included) was popped, outranked and dropped without a word.
    """
    span = to_otel_genai(source)[0]
    for attribute in span["attributes"]:
        if attribute["key"] == semconv.PROMPT:
            attribute["value"] = {"stringValue": "plan it"}

    event = otel_genai_events([span])[0]
    assert event.inputs == {"value": "plan it"}, "scalar precedence is unchanged"
    turns = event.attributes[semconv.INPUT_MESSAGES]
    assert [turn["role"] for turn in turns] == ["system", "user"]
    assert "be careful" in str(turns), "the system prompt the scalar never carried"
    assert event.attributes["opentine.import_warnings"] == [
        f"span carries both a classic scalar and {semconv.INPUT_MESSAGES}"
    ]
