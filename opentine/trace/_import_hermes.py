"""Import a Nous Research Hermes Agent trajectory (``--format hermes-trajectory``).

Hermes saves trajectories as ShareGPT-style JSONL (``trajectory_samples.jsonl``,
``failed_trajectories.jsonl`` and the batch runner's files), one session per
line: ``{"conversations": [{"from", "value"}...], "timestamp", "model",
"completed"}`` with roles ``system``/``human``/``gpt``/``tool``. A ``gpt`` turn
carries its tool calls as ``<tool_call>{"name", "arguments"}</tool_call>``
blocks and a leading ``<think>`` block; a ``tool`` turn carries results as
``<tool_response>{"tool_call_id", "name", "content"}</tool_response>`` blocks
(hermes-agent.nousresearch.com/docs/developer-guide/trajectory-format).

One record is imported: the last one, or ``FILE::N`` for record ``N`` (from 0).
The ``system`` turn is Hermes' generated template, not session content, and is
skipped. A trajectory carries no token counts, so its model steps are unpriced.

Bounded: the transcript readers' byte and line caps, at most
:data:`MAX_TURNS` turns and :data:`MAX_CALLS` tool blocks per turn, each block
at most :data:`MAX_BLOCK_CHARS` and parsed with the stdlib JSON decoder only.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from opentine.trace._transcript_common import (
    Chain,
    bounded_id,
    label,
    note_skipped,
    records,
    session_trace_id,
)
from opentine.trace.schema import TraceEvent

FORMAT = "hermes-trajectory"
MAX_TURNS = 20_000
MAX_CALLS = 64
MAX_BLOCK_CHARS = 256 * 1024
_CALL = re.compile(r"<tool_call>(.*?)</tool_call>", re.S)
_RESPONSE = re.compile(r"<tool_response>(.*?)</tool_response>", re.S)
_THINK = re.compile(r"^\s*<think>(.*?)</think>\s*", re.S)


def looks_like_hermes(item: Any) -> bool:
    turns = item.get("conversations") if isinstance(item, dict) else None
    if not isinstance(turns, list) or not turns or not isinstance(turns[0], dict):
        return False
    return "from" in turns[0] and "value" in turns[0]


def _split(source: Any) -> tuple[Any, int | None]:
    if isinstance(source, (str, Path)) and not Path(source).exists():
        head, sep, tail = str(source).rpartition("::")
        if sep and tail.isdigit() and len(tail) <= 9:
            return head, int(tail)
    return source, None


def _pick(source: Any) -> dict[str, Any]:
    path, wanted = _split(source)
    chosen: dict[str, Any] | None = None
    for index, record in enumerate(records(path)):
        if not looks_like_hermes(record):
            continue
        if wanted is None or index == wanted:
            chosen = record
        if wanted is not None and index >= wanted:
            break
    if chosen is None:
        raise ValueError("no Hermes trajectory record found" + (f" at {wanted}" if wanted else ""))
    return chosen


def _blocks(pattern: re.Pattern[str], text: str) -> tuple[list[dict[str, Any]], int]:
    found, bad = [], 0
    for match in pattern.finditer(text):
        if len(found) >= MAX_CALLS:
            bad += 1
            continue
        body = match.group(1).strip()
        try:
            value = json.loads(body) if len(body) <= MAX_BLOCK_CHARS else None
        except (ValueError, RecursionError):
            value = None
        if isinstance(value, dict):
            found.append(value)
        else:
            bad += 1
    return found, bad


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def hermes_events(source: str | Path | Iterable[Any]) -> list[TraceEvent]:
    """Events for one Hermes trajectory record (the last, or ``FILE::N``)."""
    record = _pick(source)
    model = label(record.get("model"))[:256]
    when = record.get("timestamp")
    chain = Chain(session_trace_id(f"hermes:{when}:{model}"))
    attributes = {"source": FORMAT}
    if isinstance(record.get("completed"), bool):
        attributes["hermes.completed"] = record["completed"]
    skipped = 0
    for number, turn in enumerate(record["conversations"][:MAX_TURNS]):
        if not isinstance(turn, dict):
            skipped += 1
            continue
        role, value = turn.get("from"), _text(turn.get("value"))
        span = f"turn-{number}"
        if role == "system":
            continue
        if role == "human":
            chain.add("human", when, span, actor="user", inputs={"role": "user", "text": value},
                      attributes=attributes)  # fmt: skip
        elif role == "gpt":
            think = _THINK.match(value)
            body = value[think.end() :] if think else value
            calls, bad = _blocks(_CALL, body)
            skipped += bad
            outputs: dict[str, Any] = {"text": _CALL.sub("", body).strip()}
            if think and think.group(1).strip():
                outputs["reasoning"] = think.group(1).strip()
            chain.add("model", when, span, actor="hermes", model=model, outputs=outputs,
                      attributes=attributes)  # fmt: skip
            for index, call in enumerate(calls):
                name = label(call.get("name") or "tool")
                arguments = call.get("arguments")
                chain.add("tool", when, f"{span}.call-{index}", actor=name,
                          inputs={"name": name, "arguments": arguments
                                  if isinstance(arguments, dict) else {"input": arguments}},
                          attributes=attributes)  # fmt: skip
        elif role == "tool":
            responses, bad = _blocks(_RESPONSE, value)
            skipped += bad
            for index, response in enumerate(responses):
                call_id = response.get("tool_call_id")
                chain.add("tool", when, f"{span}.result-{index}", actor=label(response.get("name")),
                          inputs={"name": label(response.get("name")),
                                  "tool_call_id": bounded_id(call_id, "call") if call_id else ""},
                          outputs={"result": _text(response.get("content"))
                                   or json.dumps(response.get("content"))},
                          attributes=attributes)  # fmt: skip
        else:
            skipped += 1
    return note_skipped(chain.events, skipped)


__all__ = ["FORMAT", "hermes_events", "looks_like_hermes"]
