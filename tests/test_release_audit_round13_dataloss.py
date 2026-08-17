"""Round-13 audit regressions: three ways content left a run without a word.

Every one is silent — exit 0, no warning, and the loss is only visible by
comparing what went in with what came back out:

* ``_cli_json.serialize``, the one JSON spelling behind ``tine export``'s
  stdout, its ``--output`` file and its OTLP body, coerced through the
  *lenient* ``json_safe``. Its depth bound replaced content with the string
  ``"[MAX_DEPTH]"`` — the right thing on import, where untrusted trace data has
  to land in the store somehow, and corruption on export, where the document is
  supposed to reproduce a run that loaded fine.
* ``_otel_logs.span_content`` popped the 1.36 message attributes, let a classic
  ``gen_ai.prompt``/``gen_ai.completion`` scalar outrank them, and then put back
  only what was still *empty* — so a span carrying both shapes lost its
  structured conversation, system prompt included, from inputs, outputs and
  attributes at once.
* ``_graph_serde.step_to_dict`` had no ``causal_ids`` slot, so exporting a v3
  repository run to ``.tine`` dropped every causal edge and a later fork of the
  reloaded run silently kept a smaller slice than the same fork of the original.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Repo, Run, StepKind, cli
from opentine._cli_json import serialize
from opentine._graph_analysis import retained_closure
from opentine.kernel import MAX_JSON_DEPTH
from opentine.trace import Recorder, TraceEvent, otel_genai_events, to_otel_genai_document
from opentine.trace import _genai_semconv as semconv

COMPAT = Path(__file__).parent / "fixtures" / "compat"

#: The deepest content a ``.tine`` can legally hold: the artifact root, its
#: ``graph``/``steps``/step record and ``inputs`` spend five of the format's
#: ``MAX_JSON_DEPTH`` levels before a step's own value gets one.
MAX_TINE_CONTENT_DEPTH = MAX_JSON_DEPTH - 5


def nest(levels: int, leaf: object = "deep-leaf") -> object:
    value: object = leaf
    for _ in range(levels):
        value = {"n": value}
    return value


# --- finding 5: export replaced deep content with a "[MAX_DEPTH]" marker ---


def test_serialize_writes_the_format_s_deepest_legal_structure_verbatim():
    # The bound the lenient coercion applied was 100 levels, reached inside the
    # export envelope long before the payload was anywhere near illegal. Parsing
    # the output back has to give the payload, not a document with a string
    # where a subtree was.
    payload = {"command": "show", "steps": [{"inputs": nest(MAX_JSON_DEPTH - 4)}]}
    written = serialize(payload)
    assert "[MAX_DEPTH]" not in written and "[CIRCULAR]" not in written
    assert json.loads(written) == payload


def test_serialize_refuses_rather_than_marking_an_illegal_structure():
    # Past the format's own bound, and cyclic: neither can be written faithfully,
    # so neither may be written at all. A marker here is a document that exits 0
    # and re-imports with the content gone.
    with pytest.raises(ValueError, match=f"nesting exceeds {MAX_JSON_DEPTH}"):
        serialize({"steps": nest(MAX_JSON_DEPTH + 1)})
    cyclic: dict[str, object] = {"command": "show"}
    cyclic["self"] = cyclic
    with pytest.raises(ValueError, match="circular reference"):
        serialize(cyclic)
    # The lenient import coercion keeps both markers: it must still accept
    # untrusted trace data instead of refusing it.
    from opentine._jsonsafe import json_safe

    assert json_safe(nest(MAX_JSON_DEPTH + 1))["n"] is not None
    assert "[MAX_DEPTH]" in json.dumps(json_safe(nest(200)))
    assert json_safe({"self": cyclic})["self"]["self"] == "[CIRCULAR]"


def test_tine_export_keeps_deep_step_content_and_re_imports_it_intact(tmp_path, monkeypatch):
    # End to end through the command. The step content below is nowhere near the
    # format's bound, but the OTLP envelope wraps every content level in four
    # JSON levels of AnyValue, so the old 100-level bound truncated it anyway.
    payload = {"api_response": nest(30)}
    run = Run(id="deep-export")
    run.add_step(StepKind.tool, payload, {"ok": True})
    source = run.save(tmp_path / "deep.tine")
    document = tmp_path / "deep.otel.json"

    monkeypatch.chdir(tmp_path)
    cli.main(["export", str(source), "--output", str(document)])
    written = document.read_text(encoding="utf-8")
    assert "[MAX_DEPTH]" not in written
    reimported = otel_genai_events(json.loads(written))
    assert reimported[0].inputs == payload, "the exported document reproduces the run"


def test_tine_export_exits_non_zero_instead_of_shipping_a_truncated_document(tmp_path, monkeypatch):
    # Content the exporter cannot render is a refusal, not a marker: nothing is
    # written, and the command's status says so.
    run = Run(id="too-deep-export")
    run.add_step(StepKind.tool, {"api_response": nest(400)}, {"ok": True})
    source = run.save(tmp_path / "verydeep.tine")
    document = tmp_path / "verydeep.otel.json"

    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["export", str(source), "--output", str(document)])
    assert exit_info.value.code == 1
    assert not document.exists(), "a refused export leaves no partial document"


def test_show_json_reproduces_the_deepest_artifact_this_build_can_load(tmp_path, capsys):
    # "Faithful for anything that legally loaded" is the whole claim, so it is
    # tested at the format's ceiling and not one level below it.
    payload = {"api_response": nest(MAX_TINE_CONTENT_DEPTH)}
    run = Run(id="deepest")
    run.add_step(StepKind.tool, payload, {"ok": True})
    source = run.save(tmp_path / "deepest.tine")
    assert Run.load(source).steps[0].inputs == payload

    cli.main(["show", str(source), "--json"])
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["steps"][0]["inputs"] == payload


# --- finding 6: a span carrying both content generations lost the modern one ---


def _string(value: str) -> dict:
    return {"stringValue": value}


def _kvlist(**fields: dict) -> dict:
    return {
        "kvlistValue": {"values": [{"key": key, "value": value} for key, value in fields.items()]}
    }


def _messages(*turns: tuple[str, str]) -> dict:
    return {
        "arrayValue": {
            "values": [_kvlist(role=_string(role), content=_string(text)) for role, text in turns]
        }
    }


SYSTEM_PROMPT = "You are a careful assistant. Never guess."


def _both_generations_span() -> dict:
    """A foreign span carrying a 1.27 scalar *and* the full 1.36 conversation.

    The scalar holds the last user turn only; the structured attribute holds the
    system prompt and the whole exchange, which is content the scalar never had.
    """
    return {
        "name": "chat",
        "traceId": "trace",
        "spanId": "both-shapes",
        "attributes": [
            {"key": semconv.OPERATION_NAME, "value": _string("chat")},
            {"key": semconv.PROMPT, "value": _string("what is 2+2?")},
            {"key": semconv.COMPLETION, "value": _string("4")},
            {
                "key": semconv.INPUT_MESSAGES,
                "value": _messages(("system", SYSTEM_PROMPT), ("user", "what is 2+2?")),
            },
            {
                "key": semconv.OUTPUT_MESSAGES,
                "value": _messages(("assistant", "4, because two twos are four.")),
            },
        ],
    }


def test_a_span_with_both_shapes_keeps_the_structured_conversation():
    event = otel_genai_events([_both_generations_span()])[0]
    # The classic scalars still win the event's content: precedence is unchanged.
    assert event.inputs == {"value": "what is 2+2?"}
    assert event.outputs == {"value": "4"}
    # And the conversation the scalars do not carry survives on the event rather
    # than being popped, outranked and dropped without a word.
    assert event.attributes[semconv.INPUT_MESSAGES] == [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "what is 2+2?"},
    ]
    assert event.attributes[semconv.OUTPUT_MESSAGES] == [
        {"role": "assistant", "content": "4, because two twos are four."}
    ]
    assert SYSTEM_PROMPT in json.dumps(event.attributes)
    assert event.attributes["opentine.import_warnings"] == [
        f"span carries both a classic scalar and {semconv.INPUT_MESSAGES}",
        f"span carries both a classic scalar and {semconv.OUTPUT_MESSAGES}",
    ]


def test_a_classic_only_and_a_structured_only_span_import_exactly_as_before():
    # The two unmixed shapes are the regression guard for the change above: they
    # must be byte-identical to the pre-fix import, warning key included.
    classic = _both_generations_span()
    classic["attributes"] = [
        item
        for item in classic["attributes"]
        if item["key"] not in {semconv.INPUT_MESSAGES, semconv.OUTPUT_MESSAGES}
    ]
    event = otel_genai_events([classic])[0]
    assert event.inputs == {"value": "what is 2+2?"} and event.outputs == {"value": "4"}
    assert event.attributes == {
        semconv.OPERATION_NAME: "chat",
        semconv.PROMPT: "what is 2+2?",
        semconv.COMPLETION: "4",
    }

    structured = _both_generations_span()
    structured["attributes"] = [
        item
        for item in structured["attributes"]
        if item["key"] not in {semconv.PROMPT, semconv.COMPLETION}
    ]
    event = otel_genai_events([structured])[0]
    assert event.inputs == {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "what is 2+2?"},
        ]
    }
    assert event.outputs == {
        "messages": [{"role": "assistant", "content": "4, because two twos are four."}]
    }
    # Consumed, because they *became* the content: no second copy, no warning.
    assert event.attributes == {semconv.OPERATION_NAME: "chat"}


def test_an_opentine_export_still_re_imports_without_a_duplicate_or_a_warning():
    # This package's own exporter writes both generations for one payload, so
    # every span it emits is a "both shapes" span. Those must stay consumed, or
    # export -> import -> export stops being a fixed point.
    run = Run(id="round-trip")
    run.add_step(StepKind.model, {"prompt": "hello"}, {"text": "hi"})
    document = to_otel_genai_document(run)
    event = otel_genai_events(document)[0]
    assert semconv.INPUT_MESSAGES not in event.attributes
    assert semconv.OUTPUT_MESSAGES not in event.attributes
    assert "opentine.import_warnings" not in event.attributes


def _tool_call_span() -> dict:
    """A foreign span whose structured assistant turn is empty content + a tool
    call, beside a non-empty classic completion scalar it does not carry."""
    tool_call = _kvlist(id=_string("call_1"), name=_string("get_weather"))
    assistant = _kvlist(
        role=_string("assistant"),
        content=_string(""),
        tool_calls={"arrayValue": {"values": [tool_call]}},
    )
    return {
        "name": "chat",
        "traceId": "trace",
        "spanId": "tool-call",
        "attributes": [
            {"key": semconv.OPERATION_NAME, "value": _string("chat")},
            {"key": semconv.PROMPT, "value": _string("weather in SF?")},
            {"key": semconv.COMPLETION, "value": _string("calling tool")},
            {"key": semconv.OUTPUT_MESSAGES, "value": {"arrayValue": {"values": [assistant]}}},
        ],
    }


def test_a_both_shapes_span_keeps_an_empty_content_tool_call_turn():
    # The classic completion scalar "calling tool" outranks the structured turn,
    # whose content is empty but which carries the tool call. An empty string is
    # a substring of every scalar, so a content-only coverage check judged the
    # turn "covered" and dropped the tool call silently — the realistic
    # empty-content tool-call shape ubiquitous in real GenAI traces.
    event = otel_genai_events([_tool_call_span()])[0]
    assert event.outputs == {"value": "calling tool"}  # precedence unchanged
    assert semconv.OUTPUT_MESSAGES in event.attributes
    assert "get_weather" in json.dumps(event.attributes[semconv.OUTPUT_MESSAGES])
    assert event.attributes["opentine.import_warnings"] == [
        f"span carries both a classic scalar and {semconv.OUTPUT_MESSAGES}"
    ]


# --- finding 7: a v3 run exported to .tine dropped every causal edge ---


def _branching_repo_run(tmp_path: Path) -> tuple[Repo, str, dict[str, str]]:
    """A repository run whose causal edge is *not* reachable through parents.

    ``D`` descends from ``C``, which branches off ``A`` beside ``B``. ``B`` is a
    causal ancestor of ``D`` and nothing else, so it is in ``D``'s fork slice
    only if the causal edge survived.
    """
    repo = Repo.init(tmp_path / "repo")
    recorder = Recorder.start(repo, capture=False)
    spans: dict[str, str] = {}
    spans["A"] = recorder.append(
        TraceEvent("model", 1.0, "t", "A", inputs={"prompt": "a"}, outputs={"text": "a"})
    )
    spans["B"] = recorder.append(
        TraceEvent("tool", 2.0, "t", "B", parent_span_id="A", inputs={"q": "b"}, outputs={"r": "b"})
    )
    spans["C"] = recorder.append(
        TraceEvent("model", 3.0, "t", "C", parent_span_id="A", inputs={"prompt": "c"}, outputs={})
    )
    spans["D"] = recorder.append(
        TraceEvent(
            "model",
            4.0,
            "t",
            "D",
            parent_span_id="C",
            causal_span_ids=("B",),
            inputs={"prompt": "d"},
            outputs={"text": "d"},
        )
    )
    return repo, recorder.finalize(), spans


def test_a_v3_run_exported_to_tine_keeps_its_causal_edges_and_fork_slice(tmp_path):
    repo, run_id, spans = _branching_repo_run(tmp_path)
    original = repo.load_run(run_id)
    assert original._v3_causal_ids[spans["D"]] == [spans["B"]]
    expected = retained_closure(original, spans["D"])
    assert spans["B"] in expected, "the causal ancestor is in the fork slice"

    exported = original.save(tmp_path / "exported.tine")
    reloaded = Run.load(exported)
    # The loss, stated first: the export dropped causal_ids outright, so B fell
    # out of the slice and the reloaded run forked a strictly smaller history
    # than the repository run it was exported from.
    assert retained_closure(reloaded, spans["D"]) == expected
    assert set(reloaded.fork(spans["D"]).graph.steps) == set(original.fork(spans["D"]).graph.steps)
    # And the edge itself round trips, still distinct from the parent edge.
    step = reloaded.get_step(spans["D"])
    assert step.causal_ids == [spans["B"]] and step.parent_ids == [spans["C"]]


def test_a_causally_exported_run_reconstructs_its_edges_back_in_a_repository(tmp_path):
    # The other direction of the same round trip: .tine -> v3 must re-attach the
    # causal edges as causal_ids on the stored event, not silently flatten them.
    repo, run_id, spans = _branching_repo_run(tmp_path)
    exported = repo.load_run(run_id).save(tmp_path / "exported.tine")

    target = Repo.init(tmp_path / "target")
    rebuilt = target.load_run(target.put_run(Run.load(exported), ref="heads/main").run_id)
    causal = {
        step.parent_ids and step.parent_ids[0] or "": step.causal_ids for step in rebuilt.steps
    }
    assert any(values for values in causal.values()), "a causal edge survived the round trip"
    assert len(retained_closure(rebuilt, rebuilt.steps[-1].id)) == len(
        retained_closure(repo.load_run(run_id), spans["D"])
    )


@pytest.mark.parametrize("version", sorted(path.name for path in COMPAT.iterdir() if path.is_dir()))
def test_artifacts_written_before_causal_ids_existed_still_load_with_none(version):
    # The compat gate's own claim, restated for the new field: it is additive and
    # absent-defaults-to-empty, so every published artifact still loads and every
    # step reports no causal edges rather than failing the read.
    run = Run.load(COMPAT / version / "artifact.tine")
    assert run.steps and all(step.causal_ids == [] for step in run.steps)
