"""The text of a run transcript, for the transcript index (0.74, release 0.73.0).

A transcript is a run's steps in order: one header line per step (sequence,
kind, tool name, model) followed by the step's input and output blobs decoded
as UTF-8 (invalid bytes replaced). Size caps keep one huge run from dominating
the index or the build time:

* ``step_bytes`` (default 2048): the first bytes of each input and output;
* ``max_bytes`` (default 32768): the whole transcript. Over it, half the
  budget goes to the first steps and half to the last, and middle steps are
  dropped, so padding at one end cannot push the other end out.

Steps repeated verbatim are kept once. An object over ``OBJECT_LIMIT``
(16 MiB) is never read into memory. Both caps are part of the index's
recorded configuration, so changing them makes the index stale.
:func:`transcript` reports what was cut (``truncated``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

STEP_BYTES = 2048
MAX_BYTES = 32768
OBJECT_LIMIT = 16 << 20


@dataclass(frozen=True)
class Caps:
    step_bytes: int = STEP_BYTES
    max_bytes: int = MAX_BYTES

    def __post_init__(self) -> None:
        if not 1 <= self.step_bytes <= self.max_bytes:
            raise ValueError("caps: 1 <= step_bytes <= max_bytes")

    def as_dict(self) -> dict[str, int]:
        return {"step_bytes": self.step_bytes, "max_bytes": self.max_bytes}


@dataclass(frozen=True)
class Transcript:
    run: str
    text: str
    steps: int
    truncated: bool


class Oversize(ValueError):
    """An object larger than ``OBJECT_LIMIT``: its size is read, never its body."""


def reader(repo: Any) -> Any:
    """Read a payload checked against its oid (no link checks): the build reads a lot.

    An object whose canonical size is over ``OBJECT_LIMIT`` raises
    :class:`Oversize` before its body is read, so one huge blob cannot exhaust
    memory; its step is indexed without that text and counted as truncated.
    """
    from opentine.kernel import ObjectEnvelope

    def read(oid: str) -> Any:
        if repo.raw_size(oid) > OBJECT_LIMIT:
            raise Oversize(oid)
        return ObjectEnvelope.decode(repo.raw(oid), oid).payload()

    return read


def _clip(raw: bytes, cap: int) -> tuple[str, bool]:
    return raw[:cap].decode("utf-8", errors="replace"), len(raw) > cap


def _blob(read: Any, oid: Any, cap: int) -> tuple[str, bool]:
    if not isinstance(oid, str) or not oid.startswith("blob:"):
        return "", False
    try:
        body = read(oid)
    except Oversize:
        return "", True
    except (KeyError, OSError, ValueError):
        return "", False
    return _clip(body, cap) if isinstance(body, bytes) else ("", False)


def _header(seq: int, step: dict[str, Any]) -> str:
    tool = step.get("tool") if isinstance(step.get("tool"), dict) else {}
    parts = [f"step {seq}", str(step.get("kind") or "")]
    if tool.get("name"):
        parts.append(f"tool {tool['name']}")
    if step.get("error"):
        parts.append("error")
    return " ".join(parts)


def _block(read: Any, seq: int, event: Any, caps: Caps) -> tuple[str, str, bool] | None:
    """``(block, body, cut)`` for one step, or None when it cannot be read."""
    if not isinstance(event, str):
        return None
    try:
        step = read(event)
    except (KeyError, OSError, ValueError):
        return None
    if not isinstance(step, dict):
        return None
    text_in, cut_in = _blob(read, step.get("input_blob"), caps.step_bytes)
    text_out, cut_out = _blob(read, step.get("output_blob"), caps.step_bytes)
    head = _header(seq, step)
    body = head.split(" ", 2)[-1] + "\n" + text_in + "\n" + text_out
    return "\n".join([head, text_in, text_out]) + "\n", body, cut_in or cut_out


def transcript(repo: Any, run: str, caps: Caps = Caps(), read: Any = None) -> Transcript:
    """The capped transcript text of the run object *run*.

    Repeated steps (same kind, tool, input and output) are kept once. Over
    ``max_bytes``, half the budget goes to the first steps and the rest to the
    last ones, so padding at either end cannot push the other end out.
    """
    read = read or reader(repo)
    try:
        payload = read(run)
    except Oversize:
        return Transcript(run, "", 0, True)
    events = payload.get("events") if isinstance(payload, dict) else None
    events = events if isinstance(events, list) else []
    seen: set[str] = set()
    state = {"cut": False, "steps": 0, "next": 0}

    def take(order: Any, budget: int, out: list[str]) -> int:
        used = 0
        for seq in order:
            state["next"] = seq + 1
            got = _block(read, seq, events[seq], caps)
            if got is None or got[1] in seen:
                continue
            seen.add(got[1])
            raw = got[0].encode("utf-8")
            state["cut"] = state["cut"] or got[2]
            state["steps"] += 1
            if used + len(raw) > budget:
                out.append(raw[: budget - used].decode("utf-8", errors="ignore"))
                state["cut"] = True
                return budget
            out.append(got[0])
            used += len(raw)
        return used

    head: list[str] = []
    tail: list[str] = []
    used = take(range(len(events)), caps.max_bytes // 2, head)
    take(range(len(events) - 1, state["next"] - 1, -1), caps.max_bytes - used, tail)
    return Transcript(run, "".join(head + tail[::-1]), state["steps"], state["cut"])


__all__ = ["MAX_BYTES", "OBJECT_LIMIT", "STEP_BYTES", "Caps", "Oversize", "Transcript", "reader",
           "transcript"]  # fmt: skip
