"""OpenTelemetry GenAI semantic-convention key names.

Single source of truth for every ``gen_ai.*`` attribute OpenTine reads on import
(:func:`opentine.trace.otel_genai_events`) and writes on export
(:func:`opentine.trace.to_otel_genai`). Both directions import these names, so a
convention update lands in one place instead of drifting between the two halves
and silently breaking the round trip.

Two convention generations are spelled here, and export emits **both** so one
document renders everywhere:

* **v1.27.0** settled the ``gen_ai.usage.input_tokens`` /
  ``gen_ai.usage.output_tokens`` counters (renamed there from
  ``gen_ai.usage.prompt_tokens`` / ``gen_ai.usage.completion_tokens``) and
  carries content on ``gen_ai.prompt`` / ``gen_ai.completion``. These are what
  SDK exporters in the wild still emit and what every deployed reader
  understands, so they are never dropped.
* **v1.36.0** moved content onto structured ``gen_ai.input.messages`` /
  ``gen_ai.output.messages``. Current backends (Arize Phoenix, Langfuse) render
  those, so export adds them alongside the 1.27 keys and declares
  :data:`SCHEMA_URL` on the exported scope.

Import additionally *reads* the vendor content shapes listed at the bottom of
this module (see :mod:`opentine.trace._otel_logs`), so a run from a current
instrumentation does not import with empty inputs and outputs. Those remain
read-only: export never invents a vendor spelling it cannot read back.
"""

from __future__ import annotations

SEMCONV_VERSION = "1.27.0"

#: Semantic-convention release that moved GenAI message content off
#: ``gen_ai.prompt``/``gen_ai.completion`` and onto structured message
#: attributes. It is the shape export declares, because it is the newest one the
#: exported spans carry.
MODERN_SEMCONV_VERSION = "1.36.0"

#: Schema URL for the exported scope, so a collector knows which convention
#: release the attributes below follow instead of guessing.
SCHEMA_URL = f"https://opentelemetry.io/schemas/{MODERN_SEMCONV_VERSION}"

NAMESPACE = "gen_ai."

OPERATION_NAME = "gen_ai.operation.name"
REQUEST_MODEL = "gen_ai.request.model"
RESPONSE_MODEL = "gen_ai.response.model"
PROMPT = "gen_ai.prompt"
COMPLETION = "gen_ai.completion"
INPUT_TOKENS = "gen_ai.usage.input_tokens"
OUTPUT_TOKENS = "gen_ai.usage.output_tokens"
TOTAL_TOKENS = "gen_ai.usage.total_tokens"

#: Token counters outside the 1.27 core. ``total_tokens`` above predates it and
#: is still emitted everywhere; the three below have no entry in any released
#: convention, so these are the spellings deployed instrumentations use —
#: ``cache_read_input_tokens`` / ``cache_creation_input_tokens`` from the
#: Anthropic-shaped exporters, ``reasoning_tokens`` from OpenLLMetry. OpenTine
#: splits cache writes by TTL, which no convention does, so the 5-minute bucket
#: takes the conventional key and the 1-hour bucket a suffixed sibling.
CACHE_READ_TOKENS = "gen_ai.usage.cache_read_input_tokens"
CACHE_WRITE_TOKENS = "gen_ai.usage.cache_creation_input_tokens"
CACHE_WRITE_1H_TOKENS = "gen_ai.usage.cache_creation_1h_input_tokens"
REASONING_TOKENS = "gen_ai.usage.reasoning_tokens"

#: OpenTine usage dimension -> GenAI token counter. Import reads right to left,
#: export writes left to right; neither side spells the keys itself. Every
#: dimension OpenTine meters is here, so usage survives a round trip whole
#: instead of collapsing to input/output.
USAGE_BY_DIMENSION: dict[str, str] = {
    "input": INPUT_TOKENS,
    "output": OUTPUT_TOKENS,
    "cache_read": CACHE_READ_TOKENS,
    "cache_write_5m": CACHE_WRITE_TOKENS,
    "cache_write_1h": CACHE_WRITE_1H_TOKENS,
    "reasoning": REASONING_TOKENS,
    "total": TOTAL_TOKENS,
}

#: Model attributes in importer preference order (response wins over request).
MODEL_KEYS: tuple[str, ...] = (RESPONSE_MODEL, REQUEST_MODEL)

#: Structured message attributes (semconv >= 1.36): arrays of
#: ``{role, parts: [{type, content}]}`` or ``{role, content}``.
INPUT_MESSAGES = "gen_ai.input.messages"
OUTPUT_MESSAGES = "gen_ai.output.messages"

#: Both structured message attributes, in ``(key, default role)`` pairs. Import
#: *consumes* these keys — their content becomes the event's inputs/outputs — and
#: export writes them back from those fields, which is what keeps an exported
#: span re-importable to the event it was written from.
MESSAGE_ATTRIBUTES: tuple[tuple[str, str], ...] = (
    (INPUT_MESSAGES, "user"),
    (OUTPUT_MESSAGES, "assistant"),
)

#: Part type for textual message content (semconv >= 1.36 message parts).
TEXT_PART = "text"

#: Per-message fields besides role/content that both directions carry through;
#: anything else stays in the span attributes rather than in the message.
CARRIED_FIELDS: tuple[str, ...] = ("id", "name", "tool_call_id", "tool_calls", "finish_reason")

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

#: The other two OpenTine-namespaced keys, for the money a run cost: the GenAI
#: conventions have no cost attribute and no billing shape, and inventing a
#: ``gen_ai.*`` one would collide with whatever the working group standardizes.
#: Spelled here with every other shared key, because both halves must agree —
#: export wrote them from the start while import ignored them, and a priced run
#: exported to OTel and read back reported $0.00 with its billing gone.
COST_ATTRIBUTE = "opentine.cost_usd"
BILLING_ATTRIBUTE = "opentine.billing"
