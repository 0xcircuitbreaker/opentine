"""Modern OTel GenAI content shapes import with real inputs and outputs.

Every span below is written the way a real exporter emits it. The last two
tests are the regression guard: a classic ``gen_ai.prompt``/``gen_ai.completion``
span, and the D1 export round trip, must import exactly as they did before the
modern readers existed.
"""

from __future__ import annotations

from opentine.trace import _genai_semconv as semconv
from opentine.trace import otel_genai_events, to_otel_genai
from opentine.trace._otel_values import attributes as _decoded


def _string(value: str) -> dict:
    return {"stringValue": value}


def _kvlist(**fields: dict) -> dict:
    return {"kvlistValue": {"values": [{"key": key, "value": v} for key, v in fields.items()]}}


def _attributes(**fields: dict) -> list[dict]:
    return [{"key": key, "value": value} for key, value in fields.items()]


def test_otel_span_events_import_prompt_and_choice_content():
    # OTel GenAI events as an SDK emits them: message events carry the prompt in
    # span-event attributes, gen_ai.choice carries the completion in a body.
    span = {
        "name": "chat gpt-5.6",
        "traceId": "trace",
        "spanId": "span",
        "startTimeUnixNano": "1000000000",
        "attributes": _attributes(**{semconv.OPERATION_NAME: _string("chat")}),
        "events": [
            {
                "name": semconv.SYSTEM_MESSAGE_EVENT,
                "attributes": _attributes(
                    content=_string("You are terse."), **{"gen_ai.system": _string("openai")}
                ),
            },
            {
                "name": semconv.USER_MESSAGE_EVENT,
                "attributes": _attributes(content=_string("2+2?"), role=_string("user")),
            },
            {
                "name": semconv.TOOL_MESSAGE_EVENT,
                "attributes": _attributes(content=_string("4"), id=_string("call_1")),
            },
            # Emitted second but indexed first: index, not arrival, orders choices.
            {
                "name": semconv.CHOICE_EVENT,
                "body": _kvlist(
                    index={"intValue": "1"},
                    finish_reason=_string("stop"),
                    message=_kvlist(role=_string("assistant"), content=_string("second")),
                ),
            },
            {
                "name": semconv.CHOICE_EVENT,
                "body": _kvlist(
                    index={"intValue": "0"},
                    finish_reason=_string("stop"),
                    message=_kvlist(role=_string("assistant"), content=_string("first")),
                ),
            },
        ],
    }
    event = otel_genai_events([span])[0]
    assert event.inputs == {
        "messages": [
            {"role": "system", "content": "You are terse."},
            {"role": "user", "content": "2+2?"},
            {"role": "tool", "content": "4", "id": "call_1"},
        ]
    }
    assert event.outputs == {
        "messages": [
            {"role": "assistant", "content": "first", "finish_reason": "stop"},
            {"role": "assistant", "content": "second", "finish_reason": "stop"},
        ]
    }


def test_otel_log_records_named_by_event_name_attribute_import():
    # Newer semconv moves the events to log records: no span-event name, an
    # event.name attribute instead, and the whole message in the body.
    span = {
        "traceId": "trace",
        "spanId": "logs",
        "logRecords": [
            {
                "attributes": _attributes(**{semconv.EVENT_NAME: _string("gen_ai.user.message")}),
                "body": _kvlist(role=_string("user"), content=_string("hi")),
            },
            {
                "attributes": _attributes(**{semconv.EVENT_NAME: _string("gen_ai.choice")}),
                "body": _kvlist(
                    finish_reason=_string("length"),
                    message=_kvlist(role=_string("assistant"), content=_string("hello")),
                ),
            },
        ],
    }
    event = otel_genai_events([span])[0]
    assert event.inputs == {"messages": [{"role": "user", "content": "hi"}]}
    assert event.outputs == {
        "messages": [{"role": "assistant", "content": "hello", "finish_reason": "length"}]
    }


def test_structured_input_output_message_attributes_import():
    # Current semconv: gen_ai.input.messages / gen_ai.output.messages, whose
    # entries use the {role, parts:[{type, content}]} form.
    span = {
        "traceId": "trace",
        "spanId": "structured",
        "attributes": _attributes(
            **{
                semconv.INPUT_MESSAGES: {
                    "arrayValue": {
                        "values": [
                            _kvlist(
                                role=_string("system"),
                                parts={
                                    "arrayValue": {
                                        "values": [
                                            _kvlist(
                                                type=_string("text"),
                                                content=_string("Be brief."),
                                            )
                                        ]
                                    }
                                },
                            ),
                            # The plain {role, content} form is equally valid.
                            _kvlist(role=_string("user"), content=_string("Why?")),
                        ]
                    }
                },
                semconv.OUTPUT_MESSAGES: {
                    "arrayValue": {
                        "values": [
                            _kvlist(
                                role=_string("assistant"),
                                finish_reason=_string("stop"),
                                parts={
                                    "arrayValue": {
                                        "values": [
                                            _kvlist(type=_string("text"), content=_string("Be")),
                                            _kvlist(type=_string("text"), content=_string("cause")),
                                        ]
                                    }
                                },
                            )
                        ]
                    }
                },
            }
        ),
    }
    event = otel_genai_events([span])[0]
    assert event.inputs == {
        "messages": [
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": "Why?"},
        ]
    }
    assert event.outputs == {
        "messages": [{"role": "assistant", "content": "Because", "finish_reason": "stop"}]
    }


def test_structured_messages_carried_as_a_json_string_import():
    # Real SDKs cannot put a structured value in an OTLP attribute, so they
    # serialize gen_ai.input/output.messages to a JSON *string*. That is the form
    # OpenLLMetry/OpenInference-style runs actually carry, and it must decode
    # rather than import empty.
    import json

    span = {
        "traceId": "trace",
        "spanId": "jsonstr",
        "attributes": _attributes(
            **{
                semconv.INPUT_MESSAGES: _string(json.dumps([{"role": "user", "content": "hi"}])),
                semconv.OUTPUT_MESSAGES: _string(
                    json.dumps([{"role": "assistant", "content": "yo", "finish_reason": "stop"}])
                ),
            }
        ),
    }
    event = otel_genai_events([span])[0]
    assert event.inputs == {"messages": [{"role": "user", "content": "hi"}]}
    assert event.outputs == {
        "messages": [{"role": "assistant", "content": "yo", "finish_reason": "stop"}]
    }
    # A string that is not JSON must degrade to empty, never raise — and the raw
    # payload is preserved in attributes rather than silently dropped: the 1.36
    # keys are consumed only when they yield content (regression guard).
    bad = {
        "traceId": "t",
        "spanId": "b",
        "attributes": _attributes(**{semconv.INPUT_MESSAGES: _string("not json at all")}),
    }
    bad_event = otel_genai_events([bad])[0]
    assert bad_event.inputs == {}
    assert bad_event.attributes[semconv.INPUT_MESSAGES] == "not json at all"


def test_openllmetry_flattened_indexed_attributes_import():
    # Traceloop/OpenLLMetry writes gen_ai.prompt.{i}.role / .content. Index 10
    # is present so ordering is numeric, not lexicographic.
    span = {
        "traceId": "trace",
        "spanId": "traceloop",
        "attributes": {
            semconv.OPERATION_NAME: "chat",
            "gen_ai.prompt.0.role": "system",
            "gen_ai.prompt.0.content": "You are helpful.",
            "gen_ai.prompt.10.role": "user",
            "gen_ai.prompt.10.content": "last",
            "gen_ai.prompt.2.role": "user",
            "gen_ai.prompt.2.content": "middle",
            "gen_ai.completion.0.role": "assistant",
            "gen_ai.completion.0.content": "ok",
            "gen_ai.completion.0.finish_reason": "stop",
            # Deeper keys stay in the attributes rather than half-flattening.
            "gen_ai.completion.0.tool_calls.0.name": "search",
        },
    }
    event = otel_genai_events([span])[0]
    assert event.inputs == {
        "messages": [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "middle"},
            {"role": "user", "content": "last"},
        ]
    }
    assert event.outputs == {
        "messages": [{"role": "assistant", "content": "ok", "finish_reason": "stop"}]
    }
    assert event.attributes["gen_ai.completion.0.tool_calls.0.name"] == "search"


def test_openinference_flattened_message_attributes_import():
    # Arize/OpenInference writes llm.input_messages.{i}.message.{field}.
    span = {
        "traceId": "trace",
        "spanId": "openinference",
        "attributes": _attributes(
            **{
                "llm.input_messages.0.message.role": _string("user"),
                "llm.input_messages.0.message.content": _string("ping"),
                "llm.input_messages.1.message.role": _string("assistant"),
                "llm.input_messages.1.message.content": _string("pong"),
                "llm.output_messages.0.message.role": _string("assistant"),
                "llm.output_messages.0.message.content": _string("pong again"),
                "openinference.span.kind": _string("LLM"),
            }
        ),
    }
    event = otel_genai_events([span])[0]
    assert event.inputs == {
        "messages": [
            {"role": "user", "content": "ping"},
            {"role": "assistant", "content": "pong"},
        ]
    }
    assert event.outputs == {"messages": [{"role": "assistant", "content": "pong again"}]}


def test_modern_content_survives_a_re_export_round_trip():
    span = {
        "traceId": "trace",
        "spanId": "roundtrip",
        "attributes": _attributes(**{semconv.OPERATION_NAME: _string("chat")}),
        "events": [
            {
                "name": semconv.USER_MESSAGE_EVENT,
                "attributes": _attributes(content=_string("hi")),
            },
            {
                "name": semconv.CHOICE_EVENT,
                "body": _kvlist(message=_kvlist(role=_string("assistant"), content=_string("yo"))),
            },
        ],
    }
    events = otel_genai_events([span])
    assert events[0].inputs == {"messages": [{"role": "user", "content": "hi"}]}
    # Export writes the normalized content back out twice: as the 1.27
    # prompt/completion attributes, and as 1.36 message arrays. The content
    # survives unchanged and the exported span is thereafter a fixed point.
    exported = to_otel_genai(events)
    assert _decoded(exported[0])[semconv.INPUT_MESSAGES] == [
        {"role": "user", "parts": [{"type": "text", "content": "hi"}]}
    ]
    assert _decoded(exported[0])[semconv.OUTPUT_MESSAGES] == [
        {"role": "assistant", "parts": [{"type": "text", "content": "yo"}]}
    ]
    reimported = otel_genai_events(exported)
    assert [event.inputs for event in reimported] == [event.inputs for event in events]
    assert [event.outputs for event in reimported] == [event.outputs for event in events]
    assert otel_genai_events(to_otel_genai(reimported)) == reimported


def test_a_span_carrying_both_generations_imports_its_content_once():
    """An OpenTine export carries 1.27 and 1.36 content side by side. The
    classic keys still win, and a message attribute is consumed rather than left
    behind as a second copy of what is now inputs/outputs — but only when it
    *is* that copy. Here the two shapes disagree on the user side ("hello"
    against "hi"), so that one is kept and flagged instead of dropped."""
    span = {
        "traceId": "trace",
        "spanId": "both",
        "attributes": _attributes(
            **{
                semconv.PROMPT: _string("hello"),
                semconv.INPUT_MESSAGES: {
                    "arrayValue": {"values": [_kvlist(role=_string("user"), content=_string("hi"))]}
                },
                semconv.OUTPUT_MESSAGES: {
                    "arrayValue": {
                        "values": [_kvlist(role=_string("assistant"), content=_string("yo"))]
                    }
                },
            }
        ),
    }
    event = otel_genai_events([span])[0]
    assert event.inputs == {"value": "hello"}, "the classic attribute still wins"
    assert event.outputs == {"messages": [{"role": "assistant", "content": "yo"}]}
    # The user side lost outright to the classic scalar, so its conversation was
    # neither used nor put back; round 13 found it vanishing from inputs,
    # outputs and attributes at once. It stays, with the disagreement noted.
    assert event.attributes[semconv.INPUT_MESSAGES] == [{"role": "user", "content": "hi"}]
    assert event.attributes["opentine.import_warnings"] == [
        f"span carries both a classic scalar and {semconv.INPUT_MESSAGES}"
    ]
    # The assistant side *became* the outputs, so its attribute is consumed.
    assert semconv.OUTPUT_MESSAGES not in event.attributes
    assert event.attributes[semconv.PROMPT] == "hello", "the 1.27 attribute is untouched"


def test_classic_prompt_and_completion_span_imports_exactly_as_before():
    """Regression: the classic shape is untouched, and still wins outright."""
    classic = {
        "name": "chat",
        "traceId": "trace",
        "spanId": "classic",
        "startTimeUnixNano": "2000000000",
        "endTimeUnixNano": "3500000000",
        "attributes": [
            {"key": semconv.OPERATION_NAME, "value": _string("chat")},
            {"key": semconv.REQUEST_MODEL, "value": _string("gpt-5.6")},
            {
                "key": semconv.PROMPT,
                "value": {
                    "arrayValue": {
                        "values": [_kvlist(role=_string("user"), content=_string("hello"))]
                    }
                },
            },
            {"key": semconv.COMPLETION, "value": _string("hi")},
        ],
    }
    event = otel_genai_events([classic])[0]
    # Byte-for-byte the pre-D3 behavior: the list prompt wraps into "messages",
    # and the scalar completion wraps into "value".
    assert event.inputs == {"messages": [{"role": "user", "content": "hello"}]}
    assert event.outputs == {"value": "hi"}

    # Same span with modern shapes bolted on: the classic content still wins.
    shadowed = dict(classic)
    shadowed["events"] = [
        {"name": semconv.USER_MESSAGE_EVENT, "attributes": _attributes(content=_string("ignored"))},
        {
            "name": semconv.CHOICE_EVENT,
            "body": _kvlist(message=_kvlist(role=_string("assistant"), content=_string("ignored"))),
        },
    ]
    assert otel_genai_events([shadowed])[0].inputs == event.inputs
    assert otel_genai_events([shadowed])[0].outputs == event.outputs


def test_content_free_span_still_imports_with_empty_inputs_and_outputs():
    event = otel_genai_events(
        [
            {
                "traceId": "trace",
                "spanId": "bare",
                "attributes": _attributes(**{semconv.OPERATION_NAME: _string("chat")}),
                "events": [{"name": "exception", "attributes": _attributes()}],
            }
        ]
    )[0]
    assert event.inputs == {} and event.outputs == {}
