"""Prompt-prefix splitting: a step's system prompt and tool definitions as own blobs.

An agent sends the same system prompt and tool list with every model call, so a
step's recorded request repeats kilobytes of identical text per turn and per
run. At record time (0.38.0+) each top-level :data:`SPLIT_KEYS` entry of a
step's inputs whose value is a non-empty string, array or object is stored as
its own blob holding the one-key object ``{key: value}``, and the event names it
under ``input_parts`` (``{key: blob oid}``); ``input_blob`` holds the remaining
keys. Content addressing then stores one copy per distinct prompt or tool list.

Readers call :func:`join_inputs`, which merges the parts back, so every consumer
(show, export, replay, search, fork edits) sees the full request. An event
without ``input_parts`` -- every event written before 0.38.0 -- is read exactly
as before, and its id is unchanged. SPEC 1.5.2 states the encoding.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

#: The request fields split out: Anthropic ``system``, OpenAI Responses
#: ``instructions``, and every dialect's ``tools``. Sorted, as stored.
SPLIT_KEYS = ("instructions", "system", "tools")
PARTS_FIELD = "input_parts"


def _splittable(value: Any) -> bool:
    return isinstance(value, (str, list, dict)) and bool(value)


def split_inputs(inputs: Any, write: Callable[[Any], str]) -> tuple[str, dict[str, str] | None]:
    """``(input_blob, input_parts or None)`` for *inputs*, written with *write*.

    *write* is the caller's own JSON blob writer, so a part is guarded and
    redacted exactly as the whole input would have been.
    """
    if not isinstance(inputs, dict):
        return write(inputs), None
    split = [key for key in SPLIT_KEYS if _splittable(inputs.get(key))]
    if not split:
        return write(inputs), None
    parts = {key: write({key: inputs[key]}) for key in split}
    rest = {key: value for key, value in inputs.items() if key not in parts}
    return write(rest), parts


def put_event_inputs(
    payload: dict[str, Any], inputs: Any, write: Callable[[Any], str]
) -> dict[str, Any]:
    """Set ``input_blob`` (and ``input_parts`` when split) on an event *payload*."""
    payload.pop(PARTS_FIELD, None)
    payload["input_blob"], parts = split_inputs(inputs, write)
    if parts:
        payload[PARTS_FIELD] = parts
    return payload


def join_inputs(
    inputs: dict[str, Any], event: dict[str, Any], read: Callable[[str], dict[str, Any]]
) -> dict[str, Any]:
    """*inputs* (decoded ``input_blob``) with *event*'s ``input_parts`` merged back.

    A part must be a one-key object naming its own key, for a key the base
    inputs do not already hold: anything else is refused rather than guessed at.
    """
    parts = event.get(PARTS_FIELD)
    if parts is None:
        return inputs
    if not isinstance(parts, dict) or not parts:
        raise ValueError("event input_parts must be a non-empty object")
    joined = dict(inputs)
    for key in sorted(parts):
        oid = parts[key]
        if key not in SPLIT_KEYS or not isinstance(oid, str) or not oid:
            raise ValueError(f"event input_parts names an unknown part: {key!r}")
        part = read(oid)
        if not isinstance(part, dict) or list(part) != [key] or key in joined:
            raise ValueError(f"event input part {key!r} does not hold exactly that field")
        joined[key] = part[key]
    return joined


__all__ = ["PARTS_FIELD", "SPLIT_KEYS", "join_inputs", "put_event_inputs", "split_inputs"]
