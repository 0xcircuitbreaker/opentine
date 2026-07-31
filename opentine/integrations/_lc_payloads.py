"""Defensive extraction of LangChain payloads, without importing LangChain.

Every value langchain-core hands a callback is read duck-typed through
:func:`attribute`, which accepts a plain mapping just as readily as a
``BaseMessage``/``LLMResult``/``AgentAction`` instance. That buys two things:
the translation is testable with dictionaries alone (no optional dependency in
the test path), and a langchain release that renames or restructures a class
degrades to a partial record instead of raising inside somebody's agent run.
"""

from __future__ import annotations

from typing import Any

MAX_TEXT_CHARS = 100_000
MAX_ITEMS = 256
_MAX_SAFE_INTEGER = (1 << 53) - 1

#: Canonical OpenTine usage dimension -> the source keys that carry it, in
#: precedence order. Covers ``llm_output["token_usage"]`` (OpenAI shape),
#: ``llm_output["usage"]`` (Anthropic shape) and ``message.usage_metadata``
#: (langchain's normalized shape, including its nested ``*_token_details``).
_USAGE_ALIASES = (
    ("input", ("input_tokens", "prompt_tokens")),
    ("output", ("output_tokens", "completion_tokens")),
    ("total", ("total_tokens",)),
    ("cache_read", ("cache_read_input_tokens", "cache_read")),
    ("cache_write_5m", ("cache_creation_input_tokens", "cache_creation")),
    ("reasoning", ("reasoning_tokens", "reasoning")),
)
_MODEL_KEYS = ("model_name", "model", "model_id", "deployment_name")


def attribute(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, dict):
        return source.get(name, default)
    return getattr(source, name, default)


def text_value(value: Any) -> Any:
    """Bound a free-text payload, leaving structured values to ``json_safe``."""
    if isinstance(value, str):
        return value if len(value) <= MAX_TEXT_CHARS else value[:MAX_TEXT_CHARS] + "[truncated]"
    if value is None or isinstance(value, (bool, int, float, dict, list, tuple)):
        return value
    content = attribute(value, "content")
    if isinstance(content, (str, list, dict)):
        return text_value(content)
    try:
        return text_value(str(value))
    except Exception as exc:  # a __str__ that raises must not break the run
        return f"[unrepresentable {type(value).__name__}: {type(exc).__name__}]"


def rows(value: Any) -> list[list[Any]]:
    """Normalize langchain's list-of-lists payloads, tolerating a flat list."""
    if not isinstance(value, (list, tuple)):
        return []
    result: list[list[Any]] = []
    for row in list(value)[:MAX_ITEMS]:
        result.append(list(row)[:MAX_ITEMS] if isinstance(row, (list, tuple)) else [row])
    return result


def run_name(serialized: Any, explicit: Any, extra: Any, default: str) -> str:
    """The framework's name for a run -- what ``framework_events`` reads as ``actor``."""
    candidates = [explicit, attribute(extra, "name")]
    data = serialized if isinstance(serialized, dict) else {}
    candidates.append(data.get("name"))
    for value in candidates:
        if isinstance(value, str) and value:
            return value
    identifier = data.get("id")
    if isinstance(identifier, (list, tuple)) and identifier:
        return str(identifier[-1])
    return default


def model_name(serialized: Any, metadata: Any, extra: Any) -> str:
    """The model behind an LLM run, from whichever slot this version populates."""
    meta = metadata if isinstance(metadata, dict) else {}
    for key in ("ls_model_name", *_MODEL_KEYS):
        value = meta.get(key)
        if isinstance(value, str) and value:
            return value
    data = serialized if isinstance(serialized, dict) else {}
    nested = data.get("kwargs")
    params = attribute(extra, "invocation_params")
    for source in (params, nested, data):
        if not isinstance(source, dict):
            continue
        for key in _MODEL_KEYS:
            value = source.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def token_usage(raw: Any) -> dict[str, int]:
    """Map a provider/langchain usage report onto OpenTine's usage dimensions."""
    source = dict(raw) if isinstance(raw, dict) else {}
    for key in ("input_token_details", "output_token_details"):
        nested = source.get(key)
        if isinstance(nested, dict):
            for name, value in nested.items():
                source.setdefault(str(name), value)
    usage: dict[str, int] = {}
    for dimension, names in _USAGE_ALIASES:
        for name in names:
            value = source.get(name)
            if type(value) is int and 0 <= value <= _MAX_SAFE_INTEGER:
                usage[dimension] = value
                break
    return usage


def message_payload(value: Any) -> Any:
    """One chat message as a JSON object, whether it arrives as an object or a dict."""
    if isinstance(value, dict):
        return value
    role = attribute(value, "type") or attribute(value, "role") or type(value).__name__
    payload: dict[str, Any] = {
        "role": str(role),
        "content": text_value(attribute(value, "content")),
    }
    for name in ("name", "tool_calls", "tool_call_id"):
        extra = attribute(value, name)
        if extra:
            payload[name] = extra
    return payload


def message_rows(messages: Any) -> Any:
    """``on_chat_model_start`` batches: unwrap the common single-prompt case."""
    converted = [[message_payload(item) for item in row] for row in rows(messages)]
    return converted[0] if len(converted) == 1 else converted


def document_payloads(documents: Any) -> list[Any]:
    result: list[Any] = []
    for document in list(documents)[:MAX_ITEMS] if isinstance(documents, (list, tuple)) else []:
        if isinstance(document, dict):
            result.append(document)
            continue
        result.append(
            {
                "page_content": text_value(attribute(document, "page_content")),
                "metadata": attribute(document, "metadata") or {},
            }
        )
    return result


def llm_result(response: Any) -> tuple[dict[str, Any], dict[str, int], str]:
    """Split an ``LLMResult`` into (outputs, usage, model)."""
    texts: list[Any] = []
    calls: list[Any] = []
    metadata_usage: dict[str, Any] = {}
    for row in rows(attribute(response, "generations")):
        for generation in row:
            message = attribute(generation, "message")
            value = attribute(generation, "text")
            texts.append(text_value(value if value is not None else attribute(message, "content")))
            tool_calls = attribute(message, "tool_calls")
            if isinstance(tool_calls, (list, tuple)):
                calls.extend(list(tool_calls)[:MAX_ITEMS])
            usage = attribute(message, "usage_metadata")
            if not metadata_usage and isinstance(usage, dict):
                metadata_usage = usage
    output = attribute(response, "llm_output")
    output = output if isinstance(output, dict) else {}
    raw = output.get("token_usage") or output.get("usage") or metadata_usage
    model = next((output[key] for key in _MODEL_KEYS if isinstance(output.get(key), str)), "")
    outputs: dict[str, Any] = {"generations": texts}
    if calls:
        outputs["tool_calls"] = calls
    return outputs, token_usage(raw), model
