"""The recorder behind ``tine mcp-proxy``: JSON-RPC messages in, run steps out.

The relay hands every message it forwards to :meth:`McpRecorder.feed`, which
never blocks: messages go on a bounded queue and are dropped (and counted) when
the queue is full. A worker thread parses them, pairs each request with its
response by JSON-RPC id, redacts the payloads *before* they reach a step (so
the content-addressed step ids hash redacted data only), and saves the run
incrementally so a killed proxy leaves a partial run on disk. A recording
failure is reported and the session carries on.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._assurance import proxy_marker, witness_save
from opentine._v4_values import mark_lenient
from opentine.core import Run, RunStatus, StepKind
from opentine.redaction import redact_text, redact_value

#: The most of one message kept for the recorder; the relay still forwards every byte.
MAX_MESSAGE = 16 * 1024 * 1024
#: Messages waiting for the worker, and requests waiting for their response.
MAX_QUEUE, MAX_PENDING = 1024, 4096
#: The least time between two incremental saves.
SAVE_INTERVAL = 0.2
CLIENT, SERVER = "client", "server"


def _key(sender: str, ident: Any) -> str:
    return sender + ":" + json.dumps(ident, sort_keys=True)


class McpRecorder:
    def __init__(
        self,
        output: Path,
        command: list[str],
        transport: str,
        report: Callable[[str], Any] = lambda message: None,
    ) -> None:
        self.output, self.transport, self._report = output, transport, report
        shown = [redact_text(part) for part in command]
        self.run = Run(user_prompt=" ".join(shown))
        self.run.metadata["mcp_proxy"] = {"command": shown, "transport": transport}
        self.run.metadata["capture"] = proxy_marker("mcp-proxy")  # checked at verify time
        mark_lenient(self.run)
        self.dropped = self.steps = 0
        self.witnessed = False
        self._queue: queue.Queue[tuple[str, bytes, float] | None] = queue.Queue(MAX_QUEUE)
        self._pending: OrderedDict[str, tuple[dict[str, Any], float]] = OrderedDict()
        self._dirty, self._saved_at = False, 0.0
        self._worker = threading.Thread(target=self._work, daemon=True)
        self._worker.start()

    def feed(self, sender: str, raw: bytes, oversize: bool = False) -> None:
        """Queue one message *sender* sent; never blocks the relay."""
        if oversize:
            raw = json.dumps({"opentine_oversize": True}).encode()
        try:
            self._queue.put_nowait((sender, raw, time.monotonic()))
        except queue.Full:
            self.dropped += 1

    def close(self, code: int) -> Run:
        """Drain the queue, record unanswered requests, and save the final run."""
        self._queue.put(None)
        self._worker.join()
        for request, started in list(self._pending.values()):
            self._step(request, None, started, time.monotonic())
        self._pending.clear()
        meta = self.run.metadata["mcp_proxy"]
        meta.update(exit_code=code, dropped=self.dropped, complete=True)
        self.run.status = RunStatus.completed if code == 0 else RunStatus.failed
        self._save()
        # The finished run is signed with the proxy key: what lifts it to T2.
        self.witnessed = witness_save(self.run, self.output)
        return self.run

    def _work(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=SAVE_INTERVAL)
            except queue.Empty:
                item = ()  # type: ignore[assignment]
            if item is None:
                return
            try:
                if item:
                    self._handle(*item)
                if self._dirty and time.monotonic() - self._saved_at >= SAVE_INTERVAL:
                    self._save()
            except Exception as exc:  # noqa: BLE001 - recording never breaks the session
                self._report(f"mcp-proxy: recording failed: {redact_text(str(exc))}")

    def _handle(self, sender: str, raw: bytes, now: float) -> None:
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            message = {"opentine_unparsed": raw[:4096].decode("utf-8", "replace")}
        for item in message if isinstance(message, list) else [message]:
            if isinstance(item, dict):
                self._message(sender, item, now)

    def _message(self, sender: str, item: dict[str, Any], now: float) -> None:
        peer = SERVER if sender == CLIENT else CLIENT
        if "method" in item and "id" in item:  # a request: wait for its response
            self._pending[_key(sender, item["id"])] = ({**item, "_sender": sender}, now)
            while len(self._pending) > MAX_PENDING:
                request, started = self._pending.popitem(last=False)[1]
                self._step(request, None, started, now)
        elif "method" in item:  # a notification
            self._step({**item, "_sender": sender}, None, now, now)
        elif "id" in item:  # a response to the peer's request
            found = self._pending.pop(_key(peer, item["id"]), None)
            if found is None:
                found = ({"method": "(unmatched response)", "_sender": peer}, now)
            self._step(found[0], item, found[1], now)
        else:
            self._step({"method": "(unrecognised message)", "_sender": sender}, item, now, now)

    def _step(self, request: dict[str, Any], reply: Any, started: float, ended: float) -> None:
        method = str(request.get("method", ""))
        inputs = {
            "method": method,
            "params": request.get("params"),
            "from": request.get("_sender"),
            "transport": self.transport,
        }
        if "id" in request:
            inputs["id"] = request["id"]
        reply = reply if isinstance(reply, dict) else {}
        outputs = {"result": reply["result"]} if "result" in reply else {}
        if not reply and not method.startswith("notifications/") and "id" in request:
            outputs = {"unanswered": True}
        if reply and "result" not in reply and "error" not in reply:
            outputs = {"message": reply}
        error = reply.get("error") if isinstance(reply.get("error"), dict) else None
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        name = params.get("name") or params.get("uri") or method
        self.run.add_step(
            StepKind.tool,
            redact_value(inputs),
            outputs=redact_value(outputs),
            duration=max(0.0, ended - started),
            tool_info={"name": redact_text(str(name)), "type": "mcp", "method": method},
            error=redact_value(error) if error else None,
        )
        self.steps += 1
        self._dirty = True

    def _save(self) -> None:
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.run.save(self.output)
        self._dirty, self._saved_at = False, time.monotonic()


__all__ = ["CLIENT", "MAX_MESSAGE", "SERVER", "McpRecorder"]
