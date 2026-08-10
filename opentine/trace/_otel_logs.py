"""Read GenAI message content out of the modern OpenTelemetry span shapes.

:func:`opentine.trace.otel_genai_events` has always sourced content from the
1.27-era ``gen_ai.prompt`` / ``gen_ai.completion`` attributes. Exporters in the
wild have moved on, and a span carrying content in any newer shape used to
import with empty ``inputs``/``outputs``. This module holds the readers for
those shapes. :func:`span_content` applies them strictly as a *fallback*: a span
that still carries the classic attributes never reaches them, so it imports
byte-identically to before this module existed.

Shapes read, in the order they are tried (per side, so a span carrying its
prompt as events and its completion as attributes still gets both):

1. **Span events / log records** — ``gen_ai.system.message``,
   ``gen_ai.user.message``, ``gen_ai.assistant.message``, ``gen_ai.tool.message``
   (inputs) and ``gen_ai.choice`` (outputs), read from ``events``, ``logs``, or
   ``logRecords``. A record holds content in its OTLP ``attributes`` or in a
   log-record ``body``; both decode through the importer's AnyValue walker.
2. **Structured message attributes** — ``gen_ai.input.messages`` /
   ``gen_ai.output.messages`` (current semconv), entries being
   ``{role, parts: [{type, content}]}`` or ``{role, content}``.
3. **Flattened indexed attributes** — OpenLLMetry's ``gen_ai.prompt.{i}.*`` and
   ``gen_ai.completion.{i}.*``, then OpenInference's ``llm.*_messages.{i}.*``.

**Normalized representation.** Every shape collapses to the ``{"messages":
[{"role", "content"}, ...]}`` mapping the JSONL and framework importers already
emit (:func:`opentine.trace._import_helpers.mapping`). ``content`` is the text
when the source gives text, else the decoded structure verbatim; the identifying
fields ``id``/``name``/``tool_call_id``/``tool_calls``/``finish_reason`` ride
along when present, and every other source field stays in the span attributes.
An absent shape yields ``{}`` so the readers compose cleanly as fallbacks.
"""

from __future__ import annotations

import json
from typing import Any

from opentine.trace import _genai_semconv as semconv
from opentine.trace._import_helpers import mapping as _mapping
from opentine.trace._otel_values import any_value
from opentine.trace._otel_values import attributes as _decode_attributes

#: Upper bound on messages taken from one span, per side. The span is already
#: size-bounded by the importer; this only stops a pathological one from
#: becoming an unbounded message list.
MAX_MESSAGES = 10_000

Messages = list[dict[str, Any]]


def span_content(
    span: dict[str, Any], attributes: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return the ``(inputs, outputs)`` an OTLP GenAI span carries: classic
    ``gen_ai.prompt``/``gen_ai.completion`` content wins, and the 1.36 message
    attributes are *consumed* so an exported span re-imports to its event — but a
    popped value that yields no content (e.g. a malformed string) is restored to
    ``attributes``, never silently dropped.
    """
    structured = {key: attributes.pop(key, None) for key, _ in semconv.MESSAGE_ATTRIBUTES}
    inputs = _mapping(span.get("inputs") or attributes.get(semconv.PROMPT))
    outputs = _mapping(span.get("outputs") or attributes.get(semconv.COMPLETION))
    if not (inputs and outputs):
        modern_inputs, modern_outputs = message_content(span, {**attributes, **structured})
        inputs, outputs = inputs or modern_inputs, outputs or modern_outputs
    filled = {"user": bool(inputs), "assistant": bool(outputs)}
    for key, side in semconv.MESSAGE_ATTRIBUTES:
        if structured.get(key) is not None and not filled[side]:
            attributes[key] = structured[key]
    return inputs, outputs


def message_content(
    span: dict[str, Any], attributes: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return ``(inputs, outputs)`` for the modern shapes this span carries.

    Either half is ``{}`` when no shape supplies it, which is what lets the
    result be used as a fallback behind the classic content attributes.
    """
    inputs: dict[str, Any] = {}
    outputs: dict[str, Any] = {}
    for read in (_from_records, _from_structured, _from_flattened):
        if inputs and outputs:
            break
        prompt, completion = read(span, attributes)
        inputs = inputs or ({"messages": prompt} if prompt else {})
        outputs = outputs or ({"messages": completion} if completion else {})
    return inputs, outputs


def _from_records(span: dict[str, Any], _attributes: dict[str, Any]) -> tuple[Messages, Messages]:
    """Read GenAI span events / log records into prompt and choice messages."""
    prompt: Messages = []
    choices: list[tuple[int, dict[str, Any]]] = []
    for position, record in enumerate(_records(span)):
        name, source = _decoded(record)
        role = semconv.MESSAGE_EVENT_ROLES.get(name)
        if role is not None:
            message = _message(source, role)
            if message is not None and len(prompt) < MAX_MESSAGES:
                prompt.append(message)
        elif name == semconv.CHOICE_EVENT and len(choices) < MAX_MESSAGES:
            message = _choice(source)
            index = source.get("index")
            if message is not None:
                choices.append((index if type(index) is int else position, message))
    # Stable sort: declared indices order the choices, the rest keep emitted order.
    return prompt, [message for _, message in sorted(choices, key=lambda item: item[0])]


def _records(span: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("events", "logs", "logRecords", "log_records"):
        value = span.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _decoded(record: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Decode one record to ``(event name, merged attribute/body mapping)``.

    A span event holds content in ``attributes``; a log record holds it in
    ``body`` and names itself with ``event.name``. A body wins on conflict.
    """
    try:
        fields = _decode_attributes(record)
        body = any_value(record.get("body"))
    except (RecursionError, ValueError):
        return "", {}
    if isinstance(body, dict):
        fields = {**fields, **body}
    elif body not in (None, ""):
        fields = {**fields, "content": body}
    name = record.get("name") or fields.get(semconv.EVENT_NAME) or ""
    return ("" if isinstance(name, (dict, list)) else str(name)), fields


def _choice(source: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a ``gen_ai.choice`` body ``{index, finish_reason, message}``."""
    nested = source.get("message")
    message = _message(nested if isinstance(nested, dict) else source, "assistant")
    reason = source.get("finish_reason")
    if message is not None and reason is not None:
        message.setdefault("finish_reason", reason)
    return message


def _from_structured(_span: dict[str, Any], values: dict[str, Any]) -> tuple[Messages, Messages]:
    """Read the current-semconv ``gen_ai.input.messages`` / ``output.messages``."""
    return (
        _messages(values.get(semconv.INPUT_MESSAGES)),
        _messages(values.get(semconv.OUTPUT_MESSAGES)),
    )


def _messages(value: Any) -> Messages:
    # SDKs serialize the message array to a JSON string; decode it back first.
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, RecursionError):
            return []
    entries = [value] if isinstance(value, dict) else value
    return _collect(entries) if isinstance(entries, list) else []


def _collect(entries: list[Any]) -> Messages:
    result: Messages = []
    for entry in entries[:MAX_MESSAGES]:
        message = _message(entry, "") if isinstance(entry, dict) else None
        if message is not None:
            result.append(message)
    return result


def _from_flattened(_span: dict[str, Any], values: dict[str, Any]) -> tuple[Messages, Messages]:
    """Read the indexed attributes OpenLLMetry and OpenInference emit.

    Each side takes the first convention that yields anything, so a span using
    one convention is never mixed with stray keys from the other.
    """
    sides: list[Messages] = []
    for specs in (semconv.FLATTENED_INPUTS, semconv.FLATTENED_OUTPUTS):
        found: Messages = []
        for prefix, infix in specs:
            found = found or _flattened(values, prefix, infix)
        sides.append(found)
    return sides[0], sides[1]


def _flattened(attributes: dict[str, Any], prefix: str, infix: str) -> Messages:
    """Group ``{prefix}.{index}[.{infix}].{field}`` attributes into messages.

    Only single-segment fields are collected, so a deeper key such as
    ``gen_ai.prompt.0.tool_calls.0.name`` stays where it is (in the span
    attributes) instead of being half-flattened into the message.
    """
    head = f"{prefix}."
    grouped: dict[int, dict[str, Any]] = {}
    for key, value in attributes.items():
        if not isinstance(key, str) or not key.startswith(head):
            continue
        index, _, field = key[len(head) :].partition(".")
        if infix:
            marker, _, field = field.partition(".")
            if marker != infix:
                continue
        if not index.isdigit() or not field or "." in field:
            continue
        grouped.setdefault(int(index), {})[field] = value
    return _collect([grouped[index] for index in sorted(grouped)])


def _message(source: dict[str, Any], default_role: str) -> dict[str, Any] | None:
    """Normalize one source message, or ``None`` when it carries nothing."""
    role = source.get("role")
    content = source.get("content")
    if content is None and "parts" in source:
        content = _parts(source.get("parts"))
    if content is None and not role and not any(f in source for f in semconv.CARRIED_FIELDS):
        return None
    message: dict[str, Any] = {
        "role": str(role) if role not in (None, "") else default_role,
        "content": "" if content is None else content,
    }
    for field in semconv.CARRIED_FIELDS:
        if source.get(field) is not None:
            message[field] = source[field]
    return message


def _parts(value: Any) -> Any:
    """Collapse semconv message parts to content.

    An all-text part list becomes the concatenated text, the form every other
    OpenTine importer produces. Anything else (tool calls, images, mixed parts)
    is returned untouched so no content is discarded.
    """
    if not isinstance(value, list) or not value:
        return value
    texts = [
        part["content"]
        for part in value
        if isinstance(part, dict)
        and str(part.get("type", "text")) == "text"
        and isinstance(part.get("content"), str)
    ]
    return "".join(texts) if len(texts) == len(value) else value
