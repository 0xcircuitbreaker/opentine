"""Decide which content shape an OTLP GenAI span's event is built from.

:mod:`opentine.trace._otel_logs` holds the *readers* for the modern shapes; this
module holds the one policy that arbitrates between them and the classic 1.27
``gen_ai.prompt`` / ``gen_ai.completion`` attributes, and decides what happens to
a shape it did not read from. Kept apart because those are two different jobs:
adding a reader must not require re-reasoning about precedence, and the rule
below — never drop content, whichever shape carried it — is the invariant a new
reader has to leave intact.

The hard case is a span carrying *both* generations, which is two different
situations wearing one shape. OpenTine's own exporter writes the 1.36 messages
as a rendering of the very payload it put on ``gen_ai.prompt``, so consuming
them is what makes export -> import -> export a fixed point. A foreign exporter
may instead carry a scalar prompt beside a full 1.36 conversation — system
message, earlier turns — that the scalar never held. :func:`_covered` is what
tells the two apart: the popped attribute is consumed only when the content that
won already carries every turn it holds.
"""

from __future__ import annotations

import json
from typing import Any

from opentine.trace import _genai_semconv as semconv
from opentine.trace._import_helpers import mapping as _mapping
from opentine.trace._import_helpers import note_import_warning
from opentine.trace._otel_logs import Messages, message_content, structured_messages


def span_content(
    span: dict[str, Any], attributes: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return the ``(inputs, outputs)`` an OTLP GenAI span carries: classic
    ``gen_ai.prompt``/``gen_ai.completion`` content wins, and the 1.36 message
    attributes are *consumed* so an exported span re-imports to its event — but a
    popped value the event did not consume is restored to ``attributes``, never
    silently dropped.
    """
    structured = {key: attributes.pop(key, None) for key, _ in semconv.MESSAGE_ATTRIBUTES}
    inputs = _mapping(span.get("inputs") or attributes.get(semconv.PROMPT))
    outputs = _mapping(span.get("outputs") or attributes.get(semconv.COMPLETION))
    classic = {"user": bool(inputs), "assistant": bool(outputs)}
    if not (inputs and outputs):
        modern_inputs, modern_outputs = message_content(span, {**attributes, **structured})
        inputs, outputs = inputs or modern_inputs, outputs or modern_outputs
    kept = {"user": inputs, "assistant": outputs}
    turns = dict(zip(("user", "assistant"), structured_messages(structured), strict=True))
    for key, side in semconv.MESSAGE_ATTRIBUTES:
        if structured.get(key) is None:
            continue
        # "Consumed", not merely "filled". Filled was true whenever a classic
        # scalar won, so a span carrying both shapes had its 1.36 conversation
        # popped, outranked, and then never put back: the system prompt and the
        # whole turn list left inputs, outputs and attributes at once, with
        # nothing recorded to say so.
        if turns[side] and (not classic[side] or _covered(kept[side], turns[side])):
            continue
        attributes[key] = structured[key]
        if classic[side]:
            # Two shapes for one side that do not agree: the scalar becomes the
            # event's content and the conversation stays in the attributes, so a
            # reader is told both were there rather than shown one of them.
            note_import_warning(attributes, f"span carries both a classic scalar and {key}")
    return inputs, outputs


def _covered(payload: dict[str, Any], turns: Messages) -> bool:
    """Does the content that won already carry every turn *turns* holds?

    ``opentine.trace.exporters`` renders each 1.36 message out of the same
    payload it writes to the classic attribute — a chat message verbatim, any
    other payload as its JSON text — so for a span this package exported, every
    turn's evidence is text the payload already contains and the copy adds
    nothing. A conversation the classic scalar never held is not covered.

    A turn's evidence is its rendered content AND every carried field it has
    (``tool_calls``, ``name``, a ``tool_call_id``, ...). An empty-string content
    is a substring of every text, so on its own it proves nothing: a turn with
    empty content and no carried fields is never covered — otherwise an
    assistant turn that is only a tool call would be dropped behind a non-empty
    classic scalar that never held it, which is exactly the loss this guards.
    """

    # Spelled exactly as ``exporters._text`` spells it, ensure_ascii included:
    # an escaped non-ASCII rendering would never match its own source text.
    def dumped(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, default=str)

    try:
        text = dumped(payload)
        for turn in turns:
            content = turn.get("content")
            rendered = content if isinstance(content, str) else dumped(content)
            evidence = [rendered] if rendered else []
            evidence += [
                dumped(turn[field])
                for field in semconv.CARRIED_FIELDS
                if turn.get(field) is not None
            ]
            if not evidence or any(item not in text for item in evidence):
                return False
    except (RecursionError, TypeError, ValueError):
        return False
    return True
