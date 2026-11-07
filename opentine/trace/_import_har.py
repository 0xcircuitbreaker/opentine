"""``tine import --format har``: the LLM API calls in a HAR 1.2 archive, as a run.

A browser's or proxy's HTTP Archive holds every request; only those that reach
a model API become ``model`` events. A call is recognised by its host (OpenAI,
Anthropic, Gemini, Azure OpenAI, DeepSeek, xAI) or, for a local gateway, by an
unambiguous path (``/chat/completions``, ``/messages``, ``:generateContent``).
The bodies are parsed exactly as ``tine record`` parses a proxied exchange
(:func:`opentine._record_parse.step_args`), so a HAR and a live recording of the
same call import alike. Headers and cookies are never read and the query string
is dropped (it can carry a key); bodies are redacted like a recording's.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any
from urllib.parse import urlsplit

from opentine._record_parse import step_args
from opentine.redaction import redact_value
from opentine.trace._import_guard import shape_checked
from opentine.trace._transcript_common import bounded_id, event
from opentine.trace.schema import TraceEvent

MAX_ENTRIES = 100_000
_HOSTS = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "gemini",
    "api.deepseek.com": "deepseek",
    "api.x.ai": "xai",
}
_PATHS = (
    ("/chat/completions", "openai"),
    ("/responses", "openai"),
    ("/messages", "anthropic"),
    (":generateContent", "gemini"),
    (":streamGenerateContent", "gemini"),
)


def upstream_for(url: str) -> str | None:
    """The ``tine record`` upstream a request URL belongs to, or ``None``."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host in _HOSTS:
        return _HOSTS[host]
    if host.endswith((".openai.azure.com", ".cognitiveservices.azure.com")):
        return "azure"
    path = parts.path.rstrip("/")
    return next((name for suffix, name in _PATHS if path.endswith(suffix)), None)


def _body(holder: Any, key: str) -> bytes:
    if not isinstance(holder, dict):
        return b""
    item = holder.get(key)
    if not isinstance(item, dict) or not isinstance(item.get("text"), str):
        return b""
    if str(item.get("encoding") or "").lower() == "base64":
        try:
            return base64.b64decode(item["text"], validate=True)
        except (binascii.Error, ValueError):
            return b""
    return item["text"].encode("utf-8", "replace")


def _record(entry: dict[str, Any], upstream: str) -> dict[str, Any]:
    request, response = entry.get("request") or {}, entry.get("response") or {}
    content = response.get("content") if isinstance(response, dict) else None
    status = response.get("status") if isinstance(response, dict) else 0
    record: dict[str, Any] = {
        "upstream": upstream,
        "path": urlsplit(str(request.get("url") or "")).path,
        "request": _body(request, "postData"),
        "response": _body(response, "content"),
        "content_type": str((content or {}).get("mimeType") or "")
        if isinstance(content, dict)
        else "",
        "status": status if isinstance(status, int) and status >= 0 else 0,
        "duration": max(0.0, float(entry.get("time") or 0)) / 1000.0,
    }
    if record["status"] == 0:
        record["error"] = "no response recorded"
    return record


def _entries(document: Any) -> list[dict[str, Any]]:
    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise ValueError("not a HAR archive: expected log.entries")
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"HAR archive has more than {MAX_ENTRIES} entries")
    return [entry for entry in entries if isinstance(entry, dict)]


def har_events(data: bytes | str) -> list[TraceEvent]:
    """One ``model`` event per LLM API call in the archive, in start order."""
    raw = data.encode() if isinstance(data, str) else data
    try:
        document = json.loads(shape_checked(raw).decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"not a HAR archive: {exc}") from exc
    calls = []
    for entry in _entries(document):
        request = entry.get("request")
        url = str(request.get("url") or "") if isinstance(request, dict) else ""
        upstream = upstream_for(url)
        if upstream is not None:
            calls.append((str(entry.get("startedDateTime") or ""), entry, upstream))
    if not calls:
        raise ValueError("HAR archive holds no recognised LLM API calls")
    calls.sort(key=lambda item: item[0])
    trace = bounded_id(calls[0][0] + str(len(calls)), "har")
    events = []
    for index, (started, entry, upstream) in enumerate(calls):
        args = step_args(_record(entry, upstream))
        outputs = redact_value(args["outputs"])
        if args["error"]:
            outputs["error"] = redact_value(args["error"])
        method = str((entry.get("request") or {}).get("method") or "")
        events.append(
            event(
                "model",
                started or None,
                trace,
                f"har-{index}",
                model=args["model_info"] or "",
                provider=args["provider"],
                inputs=redact_value(args["inputs"]),
                outputs=outputs,
                usage=args["usage"],
                duration=args["duration"],
                attributes={"http.method": method[:16], "har.upstream": upstream},
            )
        )
    return events


__all__ = ["har_events", "upstream_for"]
