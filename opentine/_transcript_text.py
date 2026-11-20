"""The text of a run transcript, for the transcript index (0.74, release 0.73.0).

A transcript is a run's steps in order: one header line per step (sequence,
kind, tool name, model) followed by the step's input and output blobs decoded
as UTF-8 (invalid bytes replaced). Size caps keep one huge run from dominating
the index or the build time:

* ``step_bytes`` (default 2048): the first bytes of each input and output;
* ``max_bytes`` (default 32768): the whole transcript; later steps are dropped.

Both caps are part of the index's recorded configuration, so changing them makes
the index stale. :func:`transcript` reports what was cut (``truncated``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

STEP_BYTES = 2048
MAX_BYTES = 32768


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


def reader(repo: Any) -> Any:
    """Read a payload checked against its oid (no link checks): the build reads a lot."""
    from opentine.kernel import ObjectEnvelope

    return lambda oid: ObjectEnvelope.decode(repo.raw(oid), oid).payload()


def _clip(raw: bytes, cap: int) -> tuple[str, bool]:
    return raw[:cap].decode("utf-8", errors="replace"), len(raw) > cap


def _blob(read: Any, oid: Any, cap: int) -> tuple[str, bool]:
    if not isinstance(oid, str) or not oid.startswith("blob:"):
        return "", False
    try:
        body = read(oid)
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


def transcript(repo: Any, run: str, caps: Caps = Caps(), read: Any = None) -> Transcript:
    """The capped transcript text of the run object *run*."""
    read = read or reader(repo)
    payload = read(run)
    events = payload.get("events") if isinstance(payload, dict) else None
    events = events if isinstance(events, list) else []
    pieces: list[str] = []
    size, truncated, steps = 0, False, 0
    for seq, event in enumerate(events):
        if not isinstance(event, str):
            continue
        try:
            step = read(event)
        except (KeyError, OSError, ValueError):
            continue
        if not isinstance(step, dict):
            continue
        cut_in = cut_out = False
        text_in, cut_in = _blob(read, step.get("input_blob"), caps.step_bytes)
        text_out, cut_out = _blob(read, step.get("output_blob"), caps.step_bytes)
        block = "\n".join([_header(seq, step), text_in, text_out]) + "\n"
        raw = block.encode("utf-8")
        if size + len(raw) > caps.max_bytes:
            room = caps.max_bytes - size
            if room > 0:
                pieces.append(raw[:room].decode("utf-8", errors="ignore"))
                steps += 1
            truncated = True
            break
        pieces.append(block)
        size += len(raw)
        steps += 1
        truncated = truncated or cut_in or cut_out
    return Transcript(run, "".join(pieces), steps, truncated)


__all__ = ["MAX_BYTES", "STEP_BYTES", "Caps", "Transcript", "reader", "transcript"]
