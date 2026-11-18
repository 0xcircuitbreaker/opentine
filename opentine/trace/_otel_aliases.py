"""Map OpenInference and framework attribute spellings onto GenAI conventions.

OpenInference (Arize) instrumentations -- the usual OTLP route out of the OpenAI
Agents SDK, LangGraph/LangChain and many others -- write ``llm.model_name``,
``llm.token_count.*`` and ``openinference.span.kind`` where the OTel GenAI
conventions write ``gen_ai.request.model``, ``gen_ai.usage.*`` and
``gen_ai.operation.name``. :func:`genai_aliases` adds the GenAI spelling of each
one *beside* the original, never in its place: an attribute the span already
carries in GenAI form wins, and every source attribute stays in the event's
attributes, so nothing a framework emitted is dropped on import and an exported
span carries both spellings.

:func:`fallback_content` reads OpenInference's ``input.value`` /
``output.value`` as a span's content when no GenAI or message shape carried any,
so a chain or tool span from those frameworks does not import empty.
"""

from __future__ import annotations

import json
from typing import Any

from opentine.trace import _genai_semconv as semconv

SPAN_KIND = "openinference.span.kind"

#: OpenInference span kind -> GenAI operation name. Kinds with no GenAI
#: operation (``CHAIN``, ``GUARDRAIL``, ``EVALUATOR``, ``UNKNOWN``) are left
#: unmapped, so the span keeps its own name as its operation.
OPERATION_BY_SPAN_KIND: dict[str, str] = {
    "LLM": "chat",
    "EMBEDDING": "embeddings",
    "TOOL": "execute_tool",
    "AGENT": "invoke_agent",
    "RETRIEVER": "retrieval",
}

#: OpenInference attribute -> the GenAI attribute it means. Token counts follow
#: OpenInference semantics: the prompt count *includes* cached tokens and the
#: completion count includes reasoning, which is exactly the current GenAI
#: convention's inclusive sub-counters, so they map onto those keys and the
#: usage reader splits them into OpenTine's exclusive buckets.
GENAI_BY_OPENINFERENCE: dict[str, str] = {
    "llm.model_name": semconv.REQUEST_MODEL,
    "llm.system": semconv.SYSTEM,
    "llm.provider": semconv.PROVIDER_NAME,
    "llm.token_count.prompt": semconv.INPUT_TOKENS,
    "llm.token_count.completion": semconv.OUTPUT_TOKENS,
    "llm.token_count.total": semconv.TOTAL_TOKENS,
    "llm.token_count.prompt_details.cache_read": semconv.CACHE_READ_INPUT_TOKENS,
    "llm.token_count.prompt_details.cache_write": semconv.CACHE_WRITE_INPUT_TOKENS,
    "llm.token_count.completion_details.reasoning": semconv.REASONING_OUTPUT_TOKENS,
    "tool.name": "gen_ai.tool.name",
    "tool.description": "gen_ai.tool.description",
    "tool_call.id": "gen_ai.tool.call.id",
    "agent.name": "gen_ai.agent.name",
    "session.id": "gen_ai.conversation.id",
}

INPUT_VALUE = "input.value"
OUTPUT_VALUE = "output.value"


def genai_aliases(attributes: dict[str, Any]) -> dict[str, Any]:
    """Return *attributes* with the GenAI spelling of each OpenInference key added.

    Never overwrites a key the span set itself and never removes a source key.
    """
    added: dict[str, Any] = {}
    kind = attributes.get(SPAN_KIND)
    operation = OPERATION_BY_SPAN_KIND.get(str(kind).upper()) if kind else None
    if operation and semconv.OPERATION_NAME not in attributes:
        added[semconv.OPERATION_NAME] = operation
    for source, target in GENAI_BY_OPENINFERENCE.items():
        value = attributes.get(source)
        if value is not None and target not in attributes:
            added[target] = value
    return {**attributes, **added} if added else attributes


def fallback_content(attributes: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """OpenInference ``input.value`` / ``output.value`` as ``(inputs, outputs)``."""
    return _value(attributes.get(INPUT_VALUE)), _value(attributes.get(OUTPUT_VALUE))


def _value(raw: Any) -> dict[str, Any]:
    if raw is None or raw == "":
        return {}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {"value": raw}
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    return raw if isinstance(raw, dict) else {"value": raw}
