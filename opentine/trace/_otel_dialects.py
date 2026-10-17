"""The OpenTelemetry dialects agent CLIs actually emit, mapped onto events.

The GenAI semantic conventions are one dialect among several. The agent CLIs
people run every day export their own:

* **Claude Code** -- spans ``claude_code.interaction`` / ``llm_request`` /
  ``tool`` (+ ``tool.blocked_on_user``, ``tool.execution``, ``hook``) and log
  events ``claude_code.api_request``, ``user_prompt``, ``tool_result``,
  ``tool_decision``, ``api_error``. Token counts are bare attributes
  (``input_tokens``, ``output_tokens``, ``cache_read_tokens``,
  ``cache_creation_tokens``), ``input_tokens`` *excluding* the cache, and it
  sets no ``gen_ai.usage.*`` at all -- so a Claude Code trace used to import
  every model call unpriced. (code.claude.com/docs/en/monitoring-usage)
* **Codex** -- log events ``codex.sse_event`` (``event.kind`` =
  ``response.completed`` carries ``input_token_count`` *including*
  ``cached_token_count``, ``output_token_count`` including
  ``reasoning_token_count``), ``codex.user_prompt``, ``codex.tool_result``,
  ``codex.tool_decision``; ``model`` and ``conversation.id`` on every event.
  (openai/codex codex-rs/otel/src/events/session_telemetry.rs)
* **Gemini CLI** -- ``gemini_cli.api_response`` (``input_token_count`` =
  promptTokenCount, including ``cached_content_token_count``),
  ``gemini_cli.user_prompt``, ``gemini_cli.tool_call``, ``gemini_cli.api_error``
  and the semconv ``gen_ai.client.inference.operation.details`` event, which
  repeats the call ``api_response`` already reported.
  (google-gemini/gemini-cli docs/cli/telemetry.md)

Each mapper returns the fields of one event, or ``None`` for a record that is
not a step (configuration, counters, lifecycle noise).
"""

from __future__ import annotations

from typing import Any

from opentine._local_providers import cloud_model
from opentine.trace._transcript_common import count, gemini_usage, inclusive_usage
from opentine.trace._transcript_usage import claude_tier

Fields = dict[str, Any]


def _present(**dimensions: int | None) -> dict[str, int]:
    return {name: value for name, value in dimensions.items() if value}


def claude_usage(attributes: dict[str, Any]) -> dict[str, int]:
    """Claude Code's bare counters: input excludes cache reads and writes."""
    return _present(
        input=count(attributes.get("input_tokens")),
        output=count(attributes.get("output_tokens")),
        cache_read=count(attributes.get("cache_read_tokens")),
        cache_write_5m=count(attributes.get("cache_creation_tokens")),
    )


def _ms(value: Any) -> float:
    milliseconds = count(value)
    return milliseconds / 1000 if milliseconds else 0.0


def _speed(attributes: dict[str, Any]) -> dict[str, Any]:
    speed = attributes.get("speed")
    return {"speed": speed} if speed not in (None, "", "normal", "standard") else {}


def _tier(attributes: dict[str, Any]) -> dict[str, Any]:
    tier = claude_tier(attributes.get("speed"), attributes.get("inference_geo"))
    return {"inputs": {"service_tier": tier}} if tier else {}


def claude_span(name: str, attributes: dict[str, Any]) -> Fields | None:
    """Fields for a Claude Code span, ``{"skip": True}`` for one that is not a step."""
    if name == "claude_code.llm_request":
        model = str(attributes.get("model") or attributes.get("gen_ai.request.model") or "")
        success = str(attributes.get("success", "true")).lower() != "false"
        return {
            "kind": "model" if success else "error",
            "model": model,
            "provider": "anthropic",
            "usage": claude_usage(attributes),
            **_tier(attributes),
            "outputs": {"text": attributes["response.model_output"]}
            if isinstance(attributes.get("response.model_output"), str)
            else {},
        }
    if name == "claude_code.tool":
        tool = str(attributes.get("tool_name") or "tool")
        return {"kind": "tool", "actor": tool, "inputs": {"name": tool}}
    if name == "claude_code.tool.blocked_on_user":
        return {"kind": "approval", "outputs": {"decision": attributes.get("decision")}}
    if name == "claude_code.interaction":
        prompt = attributes.get("user_prompt")
        text = prompt if isinstance(prompt, str) and prompt != "<REDACTED>" else ""
        return {"kind": "human", "inputs": {"text": text} if text else {}}
    if name == "claude_code.hook":
        return {"kind": "policy", "inputs": {"hook": attributes.get("hook_name")}}
    if name == "claude_code.tool.execution":
        return {"skip": True}  # its claude_code.tool parent is the tool step
    return None


def _claude_log(name: str, a: dict[str, Any]) -> Fields | None:
    if name == "api_request":
        extra = {"claude_code.cost_usd": a["cost_usd"]} if a.get("cost_usd") is not None else {}
        return {
            "kind": "model",
            "model": str(a.get("model") or ""),
            "provider": "anthropic",
            "usage": claude_usage(a),
            "duration": _ms(a.get("duration_ms")),
            "attributes": {**_speed(a), **extra},
            **_tier(a),
        }
    if name == "user_prompt":
        prompt = a.get("prompt")
        return {"kind": "human", "inputs": {"text": prompt} if isinstance(prompt, str) else {}}
    if name == "tool_result":
        tool = str(a.get("tool_name") or "tool")
        return {
            "kind": "tool",
            "actor": tool,
            "inputs": {"name": tool, "arguments": a.get("tool_input") or a.get("tool_parameters")},
            "outputs": {"success": a.get("success"), "error": a.get("error_type")},
            "duration": _ms(a.get("duration_ms")),
        }
    if name == "tool_decision":
        return {
            "kind": "approval",
            "inputs": {"name": a.get("tool_name")},
            "outputs": {"decision": a.get("decision")},
        }
    if name in ("api_error", "api_refusal"):
        return {
            "kind": "error",
            "model": str(a.get("model") or ""),
            "outputs": {"error": a.get("error")},
        }
    return None


def _codex_provider(a: dict[str, Any], model: str) -> str:
    # Only what the event states: a ':' in the model id is no provider (an
    # OpenAI fine-tune is ``ft:...:org::id``), and a cloud tag bills per token.
    stated = a.get("model_provider") or a.get("provider")
    if isinstance(stated, str) and stated.strip():
        return stated.strip()[:64]
    return "ollama-cloud" if cloud_model(model) else "openai"


def _codex_log(name: str, a: dict[str, Any]) -> Fields | None:
    model = str(a.get("model") or a.get("slug") or "")
    if name == "sse_event" and a.get("event.kind") == "response.completed":
        return {
            "kind": "model",
            "model": model,
            "provider": _codex_provider(a, model),
            "usage": inclusive_usage(
                a.get("input_token_count"),
                a.get("cached_token_count"),
                a.get("output_token_count"),
                a.get("reasoning_token_count"),
                a.get("cache_write_token_count"),
            ),
        }
    if name == "user_prompt":
        prompt = a.get("prompt")
        return {"kind": "human", "inputs": {"text": prompt} if isinstance(prompt, str) else {}}
    if name == "tool_result":
        tool = str(a.get("tool_name") or "tool")
        return {
            "kind": "tool",
            "actor": tool,
            "inputs": {"name": tool, "arguments": a.get("arguments")},
            "outputs": {"result": a.get("output"), "success": a.get("success")},
            "duration": _ms(a.get("duration_ms")),
        }
    if name == "tool_decision":
        return {
            "kind": "approval",
            "inputs": {"name": a.get("tool_name")},
            "outputs": {"decision": a.get("decision")},
        }
    return None


def _gemini_log(name: str, a: dict[str, Any]) -> Fields | None:
    if name == "api_response":
        return {
            "kind": "model",
            "model": str(a.get("model") or ""),
            "provider": "google",
            "usage": gemini_usage(
                a.get("input_token_count"),
                a.get("output_token_count"),
                a.get("cached_content_token_count"),
                a.get("thoughts_token_count"),
                a.get("tool_token_count"),
            ),
            "duration": _ms(a.get("duration_ms")),
            "outputs": {"text": a["response_text"]}
            if isinstance(a.get("response_text"), str)
            else {},
        }
    if name == "user_prompt":
        prompt = a.get("prompt")
        return {"kind": "human", "inputs": {"text": prompt} if isinstance(prompt, str) else {}}
    if name == "tool_call":
        tool = str(a.get("function_name") or "tool")
        return {
            "kind": "tool",
            "actor": tool,
            "inputs": {"name": tool, "arguments": a.get("function_args")},
            "outputs": {"success": a.get("success"), "decision": a.get("decision")},
            "duration": _ms(a.get("duration_ms")),
        }
    if name == "api_error":
        return {
            "kind": "error",
            "model": str(a.get("model_name") or ""),
            "outputs": {"error": a.get("error.message")},
        }
    return None


def log_fields(name: str, attributes: dict[str, Any]) -> tuple[str, Fields] | None:
    """``(dialect, fields)`` for a log event, or ``None`` when it is not a step."""
    prefix, _, short = name.rpartition(".")
    if name.startswith("codex."):
        fields = _codex_log(name.removeprefix("codex."), attributes)
        return ("codex", fields) if fields else None
    if name.startswith("gemini_cli."):
        fields = _gemini_log(name.removeprefix("gemini_cli."), attributes)
        return ("gemini", fields) if fields else None
    if prefix in ("", "claude_code"):
        fields = _claude_log(short, attributes)
        return ("claude_code", fields) if fields else None
    return None


__all__ = ["claude_span", "claude_usage", "log_fields"]
