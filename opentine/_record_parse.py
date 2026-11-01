"""Turn one proxied exchange into ``Run.add_step`` arguments for ``tine record``.

Usage normalisation is the adapters' own (:func:`openai_usage`,
:func:`anthropic_usage`); this module only finds the usage object, the model and
the reply text in a JSON body or an SSE stream.
"""

from __future__ import annotations

import json
from typing import Any

from opentine._record_proxy import UPSTREAMS
from opentine.models._usage import anthropic_usage, openai_usage


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def _sse_events(raw: bytes) -> list[dict[str, Any]]:
    events = []
    for line in raw.decode("utf-8", "replace").splitlines():
        if line.startswith("data:"):
            item = _json(line[5:].strip().encode())
            if isinstance(item, dict):
                events.append(item)
    return events


def _openai_reply(body: Any, events: list[dict[str, Any]]) -> tuple[str, str, Any]:
    if isinstance(body, dict):
        choices = body.get("choices") or [{}]
        message = choices[0].get("message") or {} if isinstance(choices[0], dict) else {}
        text = message.get("content") if isinstance(message, dict) else None
        if text is None and isinstance(body.get("output_text"), str):
            text = body["output_text"]
        return str(body.get("model") or ""), str(text or ""), body.get("usage")
    model, parts, usage = "", [], None
    for event in events:
        model = str(event.get("model") or model)
        usage = event.get("usage") or usage
        for choice in event.get("choices") or []:
            delta = choice.get("delta") if isinstance(choice, dict) else None
            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                parts.append(delta["content"])
    return model, "".join(parts), usage


def _anthropic_reply(body: Any, events: list[dict[str, Any]]) -> tuple[str, str, Any]:
    if isinstance(body, dict):
        blocks = body.get("content") or []
        text = "".join(
            b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"
        )
        return str(body.get("model") or ""), text, body.get("usage")
    model, parts, usage = "", [], {}
    for event in events:
        message = event.get("message")
        if isinstance(message, dict):
            model = str(message.get("model") or model)
            usage.update(message.get("usage") or {})
        delta = event.get("delta")
        if isinstance(delta, dict) and isinstance(delta.get("text"), str):
            parts.append(delta["text"])
        if isinstance(event.get("usage"), dict):
            usage.update(event["usage"])
    return model, "".join(parts), usage or None


def step_args(record: dict[str, Any]) -> dict[str, Any]:
    """Keyword arguments for ``add_step`` describing one model call."""
    _, _, provider, dialect = UPSTREAMS[record["upstream"]]
    request = _json(record.get("request") or b"")
    request = request if isinstance(request, dict) else {}
    raw = record.get("response") or b""
    sse = "event-stream" in str(record.get("content_type") or "")
    body = None if sse else _json(raw)
    events = _sse_events(raw) if sse else []
    reply = _anthropic_reply if dialect == "anthropic" else _openai_reply
    model, text, raw_usage = reply(body, events)
    model = model or str(request.get("model") or "")
    usage = None
    if isinstance(raw_usage, dict):
        try:
            normal = (
                anthropic_usage(raw_usage) if dialect == "anthropic" else openai_usage(raw_usage)
            )
            usage = normal.to_dict()
        except ValueError:
            usage = None
    inputs = {"path": record.get("path", "")}
    inputs.update(request)
    outputs: dict[str, Any] = {"text": text, "status": record.get("status", 0)}
    error = None
    if record.get("error"):
        error = {"type": "UpstreamError", "message": record["error"]}
    elif int(record.get("status") or 0) >= 400:
        error = {"type": "HTTPError", "message": raw[:2000].decode("utf-8", "replace")}
    return {
        "inputs": inputs,
        "outputs": outputs,
        "duration": float(record.get("duration") or 0.0),
        "model_info": model or None,
        "usage": usage,
        "provider": provider,
        "error": error,
    }
