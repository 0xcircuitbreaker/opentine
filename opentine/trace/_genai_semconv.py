"""OpenTelemetry GenAI semantic-convention key names.

Single source of truth for every ``gen_ai.*`` attribute OpenTine reads on import
(:func:`opentine.trace.otel_genai_events`) and writes on export
(:func:`opentine.trace.to_otel_genai`). Both directions import these names, so a
convention update lands in one place instead of drifting between the two halves
and silently breaking the round trip.

Targeted convention: **OpenTelemetry semantic conventions v1.27.0**, the release
that settled the ``gen_ai.usage.input_tokens`` / ``gen_ai.usage.output_tokens``
counters (renamed there from ``gen_ai.usage.prompt_tokens`` /
``gen_ai.usage.completion_tokens``). ``gen_ai.prompt`` and ``gen_ai.completion``
are the content attributes from that same generation; later releases move
content onto ``gen_ai.input.messages`` / ``gen_ai.output.messages``, but the
1.27-era keys are what SDK exporters in the wild still emit, so they stay the
shape OpenTine both accepts and produces.

Import additionally *reads* the newer content shapes listed at the bottom of
this module (see :mod:`opentine.trace._otel_logs`), so a run from a current
instrumentation does not import with empty inputs and outputs. Those are
read-only: export keeps emitting the 1.27 keys, which every reader still
understands.
"""

from __future__ import annotations

SEMCONV_VERSION = "1.27.0"

NAMESPACE = "gen_ai."

OPERATION_NAME = "gen_ai.operation.name"
REQUEST_MODEL = "gen_ai.request.model"
RESPONSE_MODEL = "gen_ai.response.model"
PROMPT = "gen_ai.prompt"
COMPLETION = "gen_ai.completion"
INPUT_TOKENS = "gen_ai.usage.input_tokens"
OUTPUT_TOKENS = "gen_ai.usage.output_tokens"

#: OpenTine usage dimension -> GenAI token counter. Import reads right to left,
#: export writes left to right; neither side spells the keys itself.
USAGE_BY_DIMENSION: dict[str, str] = {"input": INPUT_TOKENS, "output": OUTPUT_TOKENS}

#: Model attributes in importer preference order (response wins over request).
MODEL_KEYS: tuple[str, ...] = (RESPONSE_MODEL, REQUEST_MODEL)

#: Semantic-convention release that moved GenAI message content off
#: ``gen_ai.prompt``/``gen_ai.completion`` and onto structured message
#: attributes. Import reads these; export does not emit them.
MODERN_SEMCONV_VERSION = "1.36.0"

#: Structured message attributes (semconv >= 1.36): arrays of
#: ``{role, parts: [{type, content}]}`` or ``{role, content}``.
INPUT_MESSAGES = "gen_ai.input.messages"
OUTPUT_MESSAGES = "gen_ai.output.messages"

#: GenAI event names (semconv 1.27+ as span events, >= 1.36 as log records).
#: The four message events carry the conversation *sent* to the model; a
#: ``gen_ai.choice`` event carries one generated choice as
#: ``{index, finish_reason, message: {role, content}}``.
SYSTEM_MESSAGE_EVENT = "gen_ai.system.message"
USER_MESSAGE_EVENT = "gen_ai.user.message"
ASSISTANT_MESSAGE_EVENT = "gen_ai.assistant.message"
TOOL_MESSAGE_EVENT = "gen_ai.tool.message"
CHOICE_EVENT = "gen_ai.choice"

#: Attribute an OTLP log record names itself with when it has no span-event name.
EVENT_NAME = "event.name"

#: Input-side event name -> the role its content belongs to.
MESSAGE_EVENT_ROLES: dict[str, str] = {
    SYSTEM_MESSAGE_EVENT: "system",
    USER_MESSAGE_EVENT: "user",
    ASSISTANT_MESSAGE_EVENT: "assistant",
    TOOL_MESSAGE_EVENT: "tool",
}

#: Flattened indexed message attributes, as ``(prefix, infix)`` pairs matching
#: ``{prefix}.{index}[.{infix}].{field}``. Neither is an OTel convention; both
#: are what widely deployed instrumentations actually emit:
#: OpenLLMetry (Traceloop) writes ``gen_ai.prompt.0.role`` /
#: ``gen_ai.prompt.0.content`` and ``gen_ai.completion.0.*``; OpenInference
#: (Arize) writes ``llm.input_messages.0.message.role`` / ``.message.content``
#: and ``llm.output_messages.0.message.*``. Order is import preference.
OPENINFERENCE_INPUT_MESSAGES = "llm.input_messages"
OPENINFERENCE_OUTPUT_MESSAGES = "llm.output_messages"
OPENINFERENCE_INFIX = "message"
FLATTENED_INPUTS: tuple[tuple[str, str], ...] = (
    (PROMPT, ""),
    (OPENINFERENCE_INPUT_MESSAGES, OPENINFERENCE_INFIX),
)
FLATTENED_OUTPUTS: tuple[tuple[str, str], ...] = (
    (COMPLETION, ""),
    (OPENINFERENCE_OUTPUT_MESSAGES, OPENINFERENCE_INFIX),
)

#: OpenTine-namespaced (not a GenAI convention): carries a step's kind when the
#: GenAI operation name cannot express it. Export writes it; import reads it back
#: and drops it, so a natively recorded run round-trips through OTel with its
#: tool/think/error kinds intact instead of collapsing every step to "model".
KIND_ATTRIBUTE = "opentine.trace.kind"
