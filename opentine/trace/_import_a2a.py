"""``tine import --format a2a``: Agent2Agent (A2A) task traces as a run (0.49).

The A2A protocol (a2a-protocol.org, JSON-RPC 2.0 binding, spec 0.3) exchanges
``Task`` objects (``kind: "task"``, ``id``, ``contextId``, ``status`` with
``state``/``message``/``timestamp``, ``history`` of ``Message``, ``artifacts``)
and ``Message`` objects (``kind: "message"``, ``role`` ``user``|``agent``,
``parts``, ``messageId``, ``taskId``). Streaming adds ``status-update`` and
``artifact-update`` events. A source is one JSON document, a JSON array, or
JSONL; each item may be a bare object, a JSON-RPC request (``params.message``
of ``message/send``/``message/stream``) or a response (``result``). Mapping:

* a ``user`` message -> a ``human`` step; an ``agent`` message -> a ``model``
  step whose ``model`` is ``a2a`` and provider the remote agent
  (``metadata``'s ``agent`` name when present). A2A carries no token usage.
* each artifact (task ``artifacts`` or ``artifact-update``) -> a ``tool`` step,
  actor ``a2a.artifact``, its parts as outputs;
* a terminal ``failed``/``rejected`` status -> an ``error`` step;
  ``input-required``/``auth-required`` -> an ``approval`` step.

Parts keep ``text`` and ``data``; ``file`` parts keep name, MIME type and
URI (without credentials, query or fragment), never inline bytes. Messages
repeated across ``history`` and stream events are de-duplicated by ``messageId``.
Every payload is redacted.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from opentine.redaction import redact_value
from opentine.trace._import_jules import documents
from opentine.trace._transcript_common import bounded_id, event
from opentine.trace.schema import TraceEvent

MAX_ITEMS = 100_000
TEXT = 1 << 20
_PAUSE = {"input-required", "auth-required"}
_FAIL = {"failed", "rejected"}


def bare_uri(value: Any) -> str:
    """*value* without credentials, query or fragment: a presigned URL's token
    (``X-Amz-Signature``, ``sig=``, ``token=``) lives there and is never kept."""
    text = str(value or "")[:2048]
    parts = urlsplit(text)
    if not parts.scheme or not parts.netloc:
        return text.split("?", 1)[0].split("#", 1)[0]
    host = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


def _parts(parts: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for part in parts if isinstance(parts, list) else []:
        if not isinstance(part, dict):
            continue
        kind = part.get("kind") or part.get("type") or ("text" if "text" in part else "data")
        if kind == "text":
            out.append({"kind": "text", "text": str(part.get("text") or "")[:TEXT]})
        elif kind == "file":
            file = part.get("file") if isinstance(part.get("file"), dict) else {}
            keep = {k: str(file[k])[:2048] for k in ("name", "mimeType") if k in file}
            if "uri" in file:
                keep["uri"] = bare_uri(file["uri"])
            out.append({"kind": "file", **keep})
        else:
            out.append({"kind": "data", "data": part.get("data")})
    return out


def _unwrap(item: Any) -> list[dict[str, Any]]:
    """The A2A objects in one item (JSON-RPC envelopes opened)."""
    if not isinstance(item, dict):
        return []
    if "jsonrpc" in item:
        params = item.get("params") if isinstance(item.get("params"), dict) else {}
        found = [params["message"]] if isinstance(params.get("message"), dict) else []
        return found + _unwrap(item.get("result"))
    return [item]


def _kind(obj: dict[str, Any]) -> str:
    if obj.get("kind"):
        return str(obj["kind"])
    if "role" in obj and "parts" in obj:
        return "message"
    if "status" in obj and "id" in obj:
        return "task"
    return ""


class _Run:
    def __init__(self) -> None:
        self.events: list[TraceEvent] = []
        self.seen: set[str] = set()
        self.trace = ""

    def message(self, msg: dict[str, Any], when: Any = None) -> None:
        key = str(msg.get("messageId") or "")
        if key and key in self.seen:
            return
        self.seen.add(key)
        self.trace = self.trace or str(msg.get("contextId") or msg.get("taskId") or "")
        parts = redact_value(_parts(msg.get("parts")))
        meta = msg.get("metadata") if isinstance(msg.get("metadata"), dict) else {}
        span = f"message-{len(self.events)}"
        attrs = {"a2a.message_id": key[:256], "a2a.task_id": str(msg.get("taskId") or "")[:256]}
        if msg.get("role") == "user":
            self.events.append(
                event(
                    "human",
                    when,
                    "",
                    span,
                    actor="user",
                    inputs={"role": "user", "parts": parts},
                    attributes=attrs,
                )
            )
        else:
            agent = str(meta.get("agent") or "remote-agent")[:64]
            self.events.append(event("model", when, "", span, model="a2a", provider=agent,
                                     outputs={"parts": parts}, attributes=attrs))  # fmt: skip

    def artifact(self, art: Any, task: str, when: Any = None) -> None:
        if not isinstance(art, dict):
            return
        name = str(art.get("name") or art.get("artifactId") or "")[:256]
        self.events.append(event("tool", when, "", f"artifact-{len(self.events)}",
            actor="a2a.artifact", inputs={"name": name},
            outputs={"parts": redact_value(_parts(art.get("parts")))},
            attributes={"a2a.task_id": task[:256], "a2a.artifact_id":
                        str(art.get("artifactId") or "")[:256]}))  # fmt: skip

    def status(self, status: Any, task: str) -> None:
        if not isinstance(status, dict):
            return
        state, when = str(status.get("state") or ""), status.get("timestamp")
        if isinstance(status.get("message"), dict):
            self.message(status["message"], when)
        kind = "error" if state in _FAIL else "approval" if state in _PAUSE else ""
        if kind:
            self.events.append(
                event(
                    kind,
                    when,
                    "",
                    f"status-{len(self.events)}",
                    outputs={"state": state},
                    attributes={"a2a.task_id": task},
                )
            )

    def take(self, obj: dict[str, Any]) -> None:
        kind = _kind(obj)
        task = str(obj.get("taskId") or obj.get("id") or "")[:256]
        if kind == "message":
            self.message(obj)
        elif kind == "task":
            self.trace = self.trace or str(obj.get("contextId") or obj.get("id") or "")
            for msg in obj.get("history") or []:
                if isinstance(msg, dict):
                    self.message(msg)
            for art in obj.get("artifacts") or []:
                self.artifact(art, task)
            self.status(obj.get("status"), task)
        elif kind == "status-update":
            self.status(obj.get("status"), task)
        elif kind == "artifact-update":
            self.artifact(obj.get("artifact"), task)


def a2a_events(data: bytes | str) -> list[TraceEvent]:
    """Events for the A2A tasks, messages and stream events in *data*."""
    raw = data.encode() if isinstance(data, str) else data
    try:
        items = documents(raw)[:MAX_ITEMS]
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"not an A2A trace: {exc}") from exc
    run = _Run()
    for item in items:
        for obj in _unwrap(item):
            run.take(obj)
    if not run.events:
        raise ValueError("not an A2A trace: no task, message or artifact")
    trace = bounded_id(run.trace or "context", "a2a")
    return [replace(item, trace_id=trace) for item in run.events]


__all__ = ["a2a_events", "bare_uri"]
